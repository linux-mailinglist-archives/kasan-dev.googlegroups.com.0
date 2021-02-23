Return-Path: <kasan-dev+bncBDE5LFWXQAIRBBOC2WAQMGQE6MVAZ2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x937.google.com (mail-ua1-x937.google.com [IPv6:2607:f8b0:4864:20::937])
	by mail.lfdr.de (Postfix) with ESMTPS id 020E33231DD
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Feb 2021 21:09:43 +0100 (CET)
Received: by mail-ua1-x937.google.com with SMTP id c8sf7900750uac.11
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Feb 2021 12:09:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614110982; cv=pass;
        d=google.com; s=arc-20160816;
        b=N7BPDxAt7AducNIisyUyk89mma7euHfwqabeYpjX87hctNuMwuAtzAN2TzZNbhfZL2
         TROyIyD5lAK6C9lpMNyPy3jqA9zuECZKNw219f+yReDgbuiimkfaiv9NeKO3QKH73ncn
         /Sz9KZ60VjI+GDA3Sc9KhD4eX0J3q4DmhY+IuQCSU2P3oT8bD7xk2OBJYtytaZUMgOB2
         QkJDBg+LFQvrLQCFoyiNOYkZZyFjX6KGJRn393/1qiO9r4CLvBm46xDGCIAtOX52ZwsT
         CMA0NTjK0CSz5++yBC3HCqfGv5ff5P3oAUnVTdzJywv5GbjYAQEgZd87xZtV3yerih0P
         Cubg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=5G9/JI2/lWuKjEEBhClZiH1pDEFYnfyH2+d6XZHI7VU=;
        b=nQsaq2MiKoZj/cGBTtmymQmyj7+oqzAsj1zn1A8LJJUciJ9uRgOHdHg09UAq4GNDIv
         SyuF8tEa28fj+pSnosq3tYjIxCcc2tcdmpRSD+JY4HgeR7X9mYWye5bE/+g+QojGtiUP
         2Rm34Vuj+5ZP9JAJ7EWjIo+ghFeUURbwplcRsdxUc0PX3x+rSRHOnSlWLrMUA0korFY4
         YtT6tAHBXshJ+62p4hkf7g6Oc8bKPF6CtbjS773d+mTgon03eYbgBE8eUOtgz4F0pGRn
         qE/mrSeSccNmhjA6h6KOQJyLyJgzUYHaXHmhV29dgFUKiQIm8g4/ubOmyv+WRpNUYD6u
         5u2w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=ed9n0peS;
       spf=pass (google.com: domain of rppt@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=rppt@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5G9/JI2/lWuKjEEBhClZiH1pDEFYnfyH2+d6XZHI7VU=;
        b=giwU6EP7I3uOR6175fuZZSjip8XufZFf0B2qVXQbS/GrPA68UtLtUx9cASJxIsSMDc
         ODQCw7fWewxiokd0LH8DoRIHWQZDFXx8/QaWYRUVzh8rj4b1m/eaXfYPVbsQd2NTsjG/
         IZLUYD+zegORcRG/uE4OmEA0FHjKpCc0rs4uKvTX93VUbcAxJaWzIQuLkbIrUNkhrf3t
         prH3HkmgKxI+QD3MMsfa6wgEDbsRGebPwckbR7FFnvBxC4bnYrOvdE80uRDb77QQQUsZ
         rpxAlDNR88TMJFBA+00LxcfRIwa3vsYCGiFFaGffZMey+LeHRqgSbcbqXsVpCpjxwEq3
         95kg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5G9/JI2/lWuKjEEBhClZiH1pDEFYnfyH2+d6XZHI7VU=;
        b=fzzGigvrc3Ym/y4ezYn0RhpaKqwyD/reiuq1mEmzR7fB7M2IkjqOu4iPUqBkHAACWu
         fHm8ZwCusnKWcWQDZUr6b8G6HNaw9iPWtsfjuHiHYra0yy2T7e0v95MHD2+fzxll+Hp8
         IlV4fphML3DwHrZHfi04AnjXIOXignAB01FWIApS/uQIREf6aU+25nAXU5HpTlR11t0x
         wwUiMJ6VF5gel9DvzSkun3dLF9BIYZikRjKFgNxhDH+xsmOSURNvtCTG2ZzsvzL5V7y0
         hyJFUICEvDClD90eV1TUe90+dDaruaDHj7tYD3CUKc72iwg9Ly2a4skRN1AOnkEqgAYO
         agyg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531TE+8eXoubawCucHS9I3J9kLapKOjvUvBY4fjE64N+013j/7r+
	DWOBgpSBVmpWyL+/GiLWGFE=
X-Google-Smtp-Source: ABdhPJwkHI8CGabTTBrdZDc2LDvr9eYHzFS7kKN/QglIOo3tck8sAoAg7tlOL2qGOgqSZg29d7aw2g==
X-Received: by 2002:a9f:2b4c:: with SMTP id q12mr8884793uaj.132.1614110982063;
        Tue, 23 Feb 2021 12:09:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:268b:: with SMTP id m133ls1070249vkm.6.gmail; Tue, 23
 Feb 2021 12:09:41 -0800 (PST)
X-Received: by 2002:a1f:9fc8:: with SMTP id i191mr17929827vke.5.1614110981555;
        Tue, 23 Feb 2021 12:09:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614110981; cv=none;
        d=google.com; s=arc-20160816;
        b=MfYlJZGFiFYfSA+n5x5LUQG04ESVwOV3+fsiBs3JwALSbWnuitlq0OgihpK0RfI2KR
         Anr9PDpF+d/V3sap2FKSEdEjBkf1nEcUA7lqlI+X/Igh1cvJVO+s6aPG0YstepH2KxDh
         ySAUhe4fTvHEG3fjfnUbl8u9bCTmJ0LdjvRWnrCiHr2h6TRt7lMLMubcVbYuJM1tqPGN
         fY6q9yvahHID1GG/QiX2jrTDYbnubChAbkhxGuVgogR1glffjTYmKqrzgjcTOcjKTmQL
         knR9rcdq3z9gvgAayyejVwHVhZXsjuyRuYPWmBTf/SPhfxCuc0UR5tltflCEkJ1evqfS
         066w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=5op8Kt67whagINL33DSIe7bo2wuZ0fdfQE/1gEwLU1Y=;
        b=R0r2PVGkMkf1TZt8x4XlMKjgSIzgr9+i/3LEA5PSUxATzRkxkYWAGcmT4zscLJZ1do
         zMmL02L+NJmSD8OMSauj5WsGhvfe6ucJ5A7cC4ILKd8XoBKrDOGNNudnQGcKQH/ZQiiC
         9S1wIhcrLlrKn9m9cakm1QMUJfPVmzjP164xavkny8PZWD/GLsbxPHyehjUAS3Mekz7T
         +bz84LCXV0+25dweeGj1KbGYgdrwPggNK2BnPRJZywV+gKYOPDJZnPNI8ekJUAt/H3Z1
         ZLOJmjJBO5nbXoxN2DZIPj0hPLeWZgBRbigpBq+cL47BJyzecv3QIFuZMFe2WBqUpLzV
         Ksag==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=ed9n0peS;
       spf=pass (google.com: domain of rppt@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=rppt@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id p16si116209vko.0.2021.02.23.12.09.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 23 Feb 2021 12:09:41 -0800 (PST)
Received-SPF: pass (google.com: domain of rppt@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0098413.ppops.net [127.0.0.1])
	by mx0b-001b2d01.pphosted.com (8.16.0.43/8.16.0.43) with SMTP id 11NK4XJi185352;
	Tue, 23 Feb 2021 15:09:27 -0500
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0b-001b2d01.pphosted.com with ESMTP id 36vkne0qgk-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 23 Feb 2021 15:09:27 -0500
Received: from m0098413.ppops.net (m0098413.ppops.net [127.0.0.1])
	by pps.reinject (8.16.0.43/8.16.0.43) with SMTP id 11NK4Zcm185531;
	Tue, 23 Feb 2021 15:09:26 -0500
Received: from ppma06fra.de.ibm.com (48.49.7a9f.ip4.static.sl-reverse.com [159.122.73.72])
	by mx0b-001b2d01.pphosted.com with ESMTP id 36vkne0qg3-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 23 Feb 2021 15:09:26 -0500
Received: from pps.filterd (ppma06fra.de.ibm.com [127.0.0.1])
	by ppma06fra.de.ibm.com (8.16.0.42/8.16.0.42) with SMTP id 11NK8RE2012157;
	Tue, 23 Feb 2021 20:09:24 GMT
Received: from b06avi18878370.portsmouth.uk.ibm.com (b06avi18878370.portsmouth.uk.ibm.com [9.149.26.194])
	by ppma06fra.de.ibm.com with ESMTP id 36tsph9hta-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 23 Feb 2021 20:09:24 +0000
Received: from d06av24.portsmouth.uk.ibm.com (d06av24.portsmouth.uk.ibm.com [9.149.105.60])
	by b06avi18878370.portsmouth.uk.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 11NK99Ll18088310
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 23 Feb 2021 20:09:09 GMT
Received: from d06av24.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 2076442047;
	Tue, 23 Feb 2021 20:09:22 +0000 (GMT)
Received: from d06av24.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 4CB394203F;
	Tue, 23 Feb 2021 20:09:17 +0000 (GMT)
Received: from linux.ibm.com (unknown [9.145.51.238])
	by d06av24.portsmouth.uk.ibm.com (Postfix) with ESMTPS;
	Tue, 23 Feb 2021 20:09:17 +0000 (GMT)
Date: Tue, 23 Feb 2021 22:09:14 +0200
From: Mike Rapoport <rppt@linux.ibm.com>
To: George Kennedy <george.kennedy@oracle.com>
Cc: David Hildenbrand <david@redhat.com>,
        Andrey Konovalov <andreyknvl@google.com>,
        Andrew Morton <akpm@linux-foundation.org>,
        Catalin Marinas <catalin.marinas@arm.com>,
        Vincenzo Frascino <vincenzo.frascino@arm.com>,
        Dmitry Vyukov <dvyukov@google.com>,
        Konrad Rzeszutek Wilk <konrad@darnok.org>,
        Will Deacon <will.deacon@arm.com>,
        Andrey Ryabinin <aryabinin@virtuozzo.com>,
        Alexander Potapenko <glider@google.com>,
        Marco Elver <elver@google.com>, Peter Collingbourne <pcc@google.com>,
        Evgenii Stepanov <eugenis@google.com>,
        Branislav Rankov <Branislav.Rankov@arm.com>,
        Kevin Brodsky <kevin.brodsky@arm.com>,
        Christoph Hellwig <hch@infradead.org>,
        kasan-dev <kasan-dev@googlegroups.com>,
        Linux ARM <linux-arm-kernel@lists.infradead.org>,
        Linux Memory Management List <linux-mm@kvack.org>,
        LKML <linux-kernel@vger.kernel.org>,
        Dhaval Giani <dhaval.giani@oracle.com>
Subject: Re: [PATCH] mm, kasan: don't poison boot memory
Message-ID: <20210223200914.GH1741768@linux.ibm.com>
References: <1ac78f02-d0af-c3ff-cc5e-72d6b074fc43@redhat.com>
 <bd7510b5-d325-b516-81a8-fbdc81a27138@oracle.com>
 <56c97056-6d8b-db0e-e303-421ee625abe3@redhat.com>
 <cb8564e8-3535-826b-2d42-b273a0d793fb@oracle.com>
 <20210222215502.GB1741768@linux.ibm.com>
 <9773282a-2854-25a4-9faa-9da5dd34e371@oracle.com>
 <20210223103321.GD1741768@linux.ibm.com>
 <3ef9892f-d657-207f-d4cf-111f98dcb55c@oracle.com>
 <20210223154758.GF1741768@linux.ibm.com>
 <3a56ba38-ce91-63a6-b57c-f1726aa1b76e@oracle.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <3a56ba38-ce91-63a6-b57c-f1726aa1b76e@oracle.com>
X-TM-AS-GCONF: 00
X-Proofpoint-Virus-Version: vendor=fsecure engine=2.50.10434:6.0.369,18.0.761
 definitions=2021-02-23_08:2021-02-23,2021-02-23 signatures=0
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 mlxscore=0 bulkscore=0
 mlxlogscore=999 impostorscore=0 lowpriorityscore=0 clxscore=1015
 phishscore=0 adultscore=0 priorityscore=1501 malwarescore=0 spamscore=0
 suspectscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2009150000 definitions=main-2102230169
X-Original-Sender: rppt@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=ed9n0peS;       spf=pass (google.com:
 domain of rppt@linux.ibm.com designates 148.163.158.5 as permitted sender)
 smtp.mailfrom=rppt@linux.ibm.com;       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

On Tue, Feb 23, 2021 at 01:05:05PM -0500, George Kennedy wrote:
> On 2/23/2021 10:47 AM, Mike Rapoport wrote:
>=20
> It now crashes here:
>=20
> [=C2=A0=C2=A0=C2=A0 0.051019] ACPI: Early table checksum verification dis=
abled
> [=C2=A0=C2=A0=C2=A0 0.056721] ACPI: RSDP 0x00000000BFBFA014 000024 (v02 B=
OCHS )
> [=C2=A0=C2=A0=C2=A0 0.057874] ACPI: XSDT 0x00000000BFBF90E8 00004C (v01 B=
OCHS BXPCFACP
> 00000001=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 01000013)
> [=C2=A0=C2=A0=C2=A0 0.059590] ACPI: FACP 0x00000000BFBF5000 000074 (v01 B=
OCHS BXPCFACP
> 00000001 BXPC 00000001)
> [=C2=A0=C2=A0=C2=A0 0.061306] ACPI: DSDT 0x00000000BFBF6000 00238D (v01 B=
OCHS BXPCDSDT
> 00000001 BXPC 00000001)
> [=C2=A0=C2=A0=C2=A0 0.063006] ACPI: FACS 0x00000000BFBFD000 000040
> [=C2=A0=C2=A0=C2=A0 0.063938] ACPI: APIC 0x00000000BFBF4000 000090 (v01 B=
OCHS BXPCAPIC
> 00000001 BXPC 00000001)
> [=C2=A0=C2=A0=C2=A0 0.065638] ACPI: HPET 0x00000000BFBF3000 000038 (v01 B=
OCHS BXPCHPET
> 00000001 BXPC 00000001)
> [=C2=A0=C2=A0=C2=A0 0.067335] ACPI: BGRT 0x00000000BE49B000 000038 (v01 I=
NTEL EDK2=C2=A0=C2=A0=C2=A0=C2=A0
> 00000002=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 01000013)
> [=C2=A0=C2=A0=C2=A0 0.069030] ACPI: iBFT 0x00000000BE453000 000800 (v01 B=
OCHS BXPCFACP
> 00000000=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 00000000)
> [=C2=A0=C2=A0=C2=A0 0.070734] XXX acpi_find_ibft_region:
> [=C2=A0=C2=A0=C2=A0 0.071468] XXX iBFT, status=3D0
> [=C2=A0=C2=A0=C2=A0 0.072073] XXX about to call acpi_put_table()...
> ibft_addr=3Dffffffffff240000
> [=C2=A0=C2=A0=C2=A0 0.073449] XXX acpi_find_ibft_region(EXIT):
> PANIC: early exception 0x0e IP 10:ffffffff9259f439 error 0 cr2
> 0xffffffffff240004

Right, I've missed the dereference of the ibft_addr after
acpi_find_ibft_region().=20

With this change to iscsi_ibft_find.c instead of the previous one it should
be better:

diff --git a/drivers/firmware/iscsi_ibft_find.c b/drivers/firmware/iscsi_ib=
ft_find.c
index 64bb94523281..1be7481d5c69 100644
--- a/drivers/firmware/iscsi_ibft_find.c
+++ b/drivers/firmware/iscsi_ibft_find.c
@@ -80,6 +80,27 @@ static int __init find_ibft_in_mem(void)
 done:
 	return len;
 }
+
+static void __init acpi_find_ibft_region(unsigned long *sizep)
+{
+	int i;
+	struct acpi_table_header *table =3D NULL;
+	acpi_status status;
+
+	if (acpi_disabled)
+		return;
+
+	for (i =3D 0; i < ARRAY_SIZE(ibft_signs) && !ibft_addr; i++) {
+		status =3D acpi_get_table(ibft_signs[i].sign, 0, &table);
+		if (ACPI_SUCCESS(status)) {
+			ibft_addr =3D (struct acpi_table_ibft *)table;
+			*sizep =3D PAGE_ALIGN(ibft_addr->header.length);
+			acpi_put_table(table);
+			break;
+		}
+	}
+}
+
 /*
  * Routine used to find the iSCSI Boot Format Table. The logical
  * kernel address is set in the ibft_addr global variable.
@@ -91,14 +112,16 @@ unsigned long __init find_ibft_region(unsigned long *s=
izep)
 	/* iBFT 1.03 section 1.4.3.1 mandates that UEFI machines will
 	 * only use ACPI for this */
=20
-	if (!efi_enabled(EFI_BOOT))
+	if (!efi_enabled(EFI_BOOT)) {
 		find_ibft_in_mem();
-
-	if (ibft_addr) {
 		*sizep =3D PAGE_ALIGN(ibft_addr->header.length);
-		return (u64)virt_to_phys(ibft_addr);
+	} else {
+		acpi_find_ibft_region(sizep);
 	}
=20
+	if (ibft_addr)
+		return (u64)virt_to_phys(ibft_addr);
+
 	*sizep =3D 0;
 	return 0;
 }

> [=C2=A0=C2=A0=C2=A0 0.075711] CPU: 0 PID: 0 Comm: swapper Not tainted 5.1=
1.0-34a2105 #8
> [=C2=A0=C2=A0=C2=A0 0.076983] Hardware name: QEMU Standard PC (i440FX + P=
IIX, 1996), BIOS
> 0.0.0 02/06/2015
> [=C2=A0=C2=A0=C2=A0 0.078579] RIP: 0010:find_ibft_region+0x470/0x577

--=20
Sincerely yours,
Mike.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20210223200914.GH1741768%40linux.ibm.com.
