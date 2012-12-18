package org.koala.util;

import java.io.OutputStream;
import java.util.HashMap;
import java.util.List;

import org.apache.poi.hssf.usermodel.HSSFCell;
import org.apache.poi.hssf.usermodel.HSSFCellStyle;
import org.apache.poi.hssf.usermodel.HSSFFont;
import org.apache.poi.hssf.usermodel.HSSFRichTextString;
import org.apache.poi.hssf.usermodel.HSSFRow;
import org.apache.poi.hssf.usermodel.HSSFSheet;
import org.apache.poi.hssf.usermodel.HSSFWorkbook;

public class ExcelUtils {
    private HSSFWorkbook wb;

    public ExcelUtils() {
        wb = new HSSFWorkbook();
    }

    /**
     * <p>
     * 单Sheet输出
     * </p>
     *
     * @param list      存放的是对象数组，数组元素可以转化为字符串，数组元素对应数据库里的列。
     * @param headNames 对象数组的描述。
     * @param out       输出流
     */
    public void outputExcel(String sheetname, List<Object[]> list,
                            String[] headNames, OutputStream out) {
        try {
            createSheet(sheetname, headNames);
            creatRow(list, 0);
            wb.write(out);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * 多sheet输出
     *
     * @param sheetNames
     * @param hmsl
     * @param hmss
     */
    public void outputExcel(String[] sheetNames,
                            HashMap<String, List<Object[]>> hmsl,
                            HashMap<String, String[]> hmss, OutputStream out) {
        try {
            for (int i = 0; i < sheetNames.length; i++) {

                if (hmsl.containsKey(sheetNames[i])
                        && hmss.containsKey(sheetNames[i])) {
                    createSheet(sheetNames[i], hmss.get(sheetNames[i]));
                    creatRow(hmsl.get(sheetNames[i]), i);
                } else
                    throw new RuntimeException(
                            "All arguments is not same number with [sheetNames].");
            }
            wb.write(out);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * <p>
     * 创建头文件
     * </p>
     *
     * @param headNames 对象数组的描述
     */
    private void createSheet(String sheetname, String[] headNames) {
        try {
            HSSFSheet sheet = wb.createSheet(sheetname);
            HSSFRow row = sheet.createRow(0);
            HSSFFont font = wb.createFont();
            font.setBoldweight(HSSFFont.BOLDWEIGHT_BOLD);
            HSSFCellStyle cellStyle = wb.createCellStyle();
            cellStyle.setFont(font);
            for (int i = 0; i < headNames.length; i++) {
                HSSFCell cell = row.createCell((short) i);
                cell.setCellStyle(cellStyle);
                HSSFRichTextString hts = new HSSFRichTextString(headNames[i]);
                cell.setCellValue(hts);
            }
        } catch (Exception ex) {
            System.out.print(ex);
        }
    }

    /**
     * 填充数据
     *
     * @param list  存放的是对象数组
     * @param index sheet的位置
     */
    private void creatRow(List<Object[]> list, int index) {
        try {
            for (int i = 0; i < list.size(); i++) {
                Object[] objs = list.get(i);
                HSSFSheet sheet = wb.getSheetAt(index);
                HSSFRow row = sheet.createRow(i + 1);
                for (int j = 0; j < objs.length; j++) {
                    HSSFCell cell = row.createCell(j);
                    cell.setCellType(HSSFCell.CELL_TYPE_STRING);
                    cell
                            .setCellValue(new HSSFRichTextString(objs[j] == null ? "" : objs[j]
                                    .toString()));
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}

	}
}
