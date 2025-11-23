package loadbalancersalgo;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

public class RoundRobin {
    static class SimpleRoundRobin{
        private final List<String>servers;
        private int index;

        SimpleRoundRobin(List<String> servers) {
            this.servers = new ArrayList<>(servers);
            this.index = 0;
        }

        public String getNextServer(){
            if(servers.isEmpty()){
                new IllegalStateException("No servers available");
            }
            String server = servers.get(index);
            index = (index + 1) % servers.size();
            return server;
        }
    }

    static class ThreadSafeRoundRobin{
        private final List<String>servers;
        private final AtomicInteger index;

        ThreadSafeRoundRobin(List<String> servers) {
            this.servers = new ArrayList<>(servers);
            this.index = new AtomicInteger(0);
        }

        public String getNextServer(){
            if(servers.isEmpty()){
                throw new IllegalStateException("No servers available");
            }
            int currentIndex = Math.abs(index.getAndIncrement()% servers.size());
            return servers.get(currentIndex);
        }
    }

    public static void main(String[] args) {
        SimpleRoundRobin lb1 = new SimpleRoundRobin(Arrays.asList("s1","s2","s3"));
        for (int i = 0; i < 7; i++) {
            System.out.println("Request " + (i+1) + " -> " + lb1.getNextServer());
        }
    }
}
