import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class LogAnalysis {

		public long[] logdata = new long[4];
		public Map<Long, Long[]> ipdata = new HashMap<Long, Long[]>();
		public Set<String> ipdatavisit = new HashSet<String>();

		public LogAnalysis() {
			logdata = new long[4];
			for (int i = 0; i < 4; i++) {
				logdata[i] = 0L;
			}
		}
		public long[] getLogdata() {
			return this.logdata;
		}

		public Map<Long, Long[]> getIpdata() {
			return ipdata;
		}

		public void setIpdata(Map<Long, Long[]> ipdata) {
			this.ipdata = ipdata;
		}

		public Set<String> getIpdatavisit() {
			return ipdatavisit;
		}

		public void setIpdatavisit(Set<String> ipdatavisit) {
			this.ipdatavisit = ipdatavisit;
		}

		/**
		 * counts one log file
		 * 
		 * @param file
		 */
		public int logAnalysis(String file,String ipFile,String sqlPath) {
			File f = new File(file);
			if(!f.exists()){
				System.out.println("file not exists.");
			}else {
				System.out.println("file exists.");
			}
			String str = "";
			ipdata.clear();
			long ipcount =0L;
			long ipcontVisits = 0; //ip cishu
			long validatePageNo = 0L;
			long fileNo = 0L;
			long downloadSize = 0L;

			if (file == null) {
				System.out.println("file is not exist");
				return -1;
			}
			try {
				BufferedReader br = new BufferedReader(new FileReader(file));
				while ((str = br.readLine()) != null) {
					String[] tempstr = str.split("\\s+");
					if (tempstr.length == 10) {
						for (int j = 0; j < tempstr.length; j++) {
							if(tempstr[j].startsWith("[")) {//time str
								String timestr=tempstr[j];
								tempstr[j]=timestr.substring(1,15);
							}
							else if (tempstr[j].startsWith("\"")) {
								int len = tempstr[j].length();
								tempstr[j] = tempstr[j].substring(1, len);
							} else if (tempstr[j].endsWith("]")
									|| tempstr[j].endsWith("\"")) {
								int len = tempstr[j].length();
								tempstr[j] = tempstr[j].substring(0, len - 1);
							}
							if (!(tempstr[j].equals("-")) && j < tempstr.length - 1) {
								if (tempstr[j].contains("'")) {
									tempstr[j] = tempstr[j]
											.replaceAll("'", "\\\\'");
								}
							}

						}
						String[] ipstart = tempstr[0].split("\\.");
						fileNo++;
						long start=0l;
						if(ipstart.length==4) {
							if(isInteger(ipstart[0])){
								start = Long.parseLong(ipstart[0]) * 256 * 256 * 256
										+ Long.parseLong(ipstart[1]) * 256 * 256
										+ Long.parseLong(ipstart[2]) * 256
										+ Long.parseLong(ipstart[3]);
							}
						}
						String visitIP = start+tempstr[3];
						ipdatavisit.add(visitIP);
						if (ipdata.containsKey(start)) {
							Long[] ipStat = ipdata.get(start);
							ipStat[0] += 1;
							if (isValidPage(tempstr[6])
									&& (isValidResponseStatus(tempstr[8]))) {
								ipdatavisit.add(visitIP);
								ipStat[1] += 1L;
								if (tempstr[9] != null && !("-".equals(tempstr[9]))) {
									ipStat[2] += Long.parseLong(tempstr[9]);
								}
								
							}
							ipdata.put(start, ipStat);
						} else {
							Long[] ipStat = new Long[3];
							ipStat[0] = 1L;
							ipStat[1] = 0L;
							ipStat[2] = 0L;
							if (isValidPage(tempstr[6])
									&& (isValidResponseStatus(tempstr[8]))) {
								ipStat[1] += 1L ;
								if(tempstr[9] != null && !("-".equals(tempstr[9]))){
									ipStat[2] = Long.parseLong(tempstr[9]);
								}
							}
							ipdata.put(start, ipStat);
						}
						
						if (isValidPage(tempstr[6])
								&& (isValidResponseStatus(tempstr[8]))) {
							validatePageNo++;
							if (tempstr[9] != null && !("-".equals(tempstr[9]))) {
								downloadSize += Long.parseLong(tempstr[9]);
							}
						}				
					}

				}
				ipcount = ipdata.size();
				logdata[0] = ipcount;
				logdata[1] = validatePageNo;
				logdata[2] = fileNo;
				logdata[3] = downloadSize;
				br.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
			return 0;
		}

	public static boolean isInteger(String str) {
			Pattern pattern = Pattern.compile("^[^a-zA-Z]*$");
			return pattern.matcher(str).matches();
		}
		public boolean isValidPage(String page){
			boolean flag = true;
			String regexp = ".+(css|js|class|gif|jpg|jpeg|png|bmp|ico|swf)$";
			Pattern pattern = Pattern.compile(regexp);
			Matcher match = pattern.matcher(page);
			if(match.matches()){
				flag = false;
			}
			return flag;
		}
		public boolean isValidResponseStatus(String status){
			String regexp = "200|304";
			Pattern pattern = Pattern.compile(regexp);
			Matcher match = pattern.matcher(status);
			return match.matches();
		}
		
		public static void main(String[] args) {
			LogAnalysis logAnalysis = new LogAnalysis();
			logAnalysis.logAnalysis(args[0],args[1],args[2]);
			System.out.println("unique IPs: "+logAnalysis.getLogdata()[0]);
			System.out.println("validated page number: "+logAnalysis.getLogdata()[1]);

		}
		

}
