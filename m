Return-Path: <kasan-dev+bncBDE5LFWXQAIRBG6Z3CAQMGQEWR6J3PI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id 6513B323AA4
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Feb 2021 11:38:21 +0100 (CET)
Received: by mail-oo1-xc39.google.com with SMTP id w3sf832295oow.8
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Feb 2021 02:38:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614163100; cv=pass;
        d=google.com; s=arc-20160816;
        b=YwF2lY5vyJyeuG5nEI1gxDDzm4NsznaaEDt5UIDoeda1w7PrjE1YPThgXKb5Bu4DdQ
         3u9eMbOUazWnPrd2bi5+gS6H/TwEGFHHoq++yTeOlWI+bAqbXp5pVc2OrjllKsffy3je
         DuS5q7piWOTd2KnHQUa7C1M/7RJZzUeLF+2iO+vRfZlAcufa28fgBnbJQ3eROE/gr9sN
         WYwMxpMrOYyMXQY8bgzYNCpkKOALGqxSvDELyzjIxJfE6ju9y5WcRSM9bAoJXgfgIwwE
         p8P/KJQ8SeiQ1guOfdVvsGqe5FR8CePxnWq/7BWFxDvhMPFEpbRtEtxgFlzS4HQcO3Hk
         XRfQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=OryZFhlF9JPSZV1QJabqqsuJwfULKt8CZF5v4dRDV24=;
        b=UVWsLLCmRQgc9puuPDUQA5iwPs3CcSRPRHTdZsUwccp6nRWmvBL6kvcy08MHJOqhDp
         9on9Svh3Ywp/Myz6AthhO0bQ4F0KX1pWEnSRB9xkMUfJpYP2oPuHIuTMafimY1qLlacB
         mBPCtwE9PrNjbtVpNHC+iXtzftndBQHM/pbduhQGYDUq7x+WhWo7nSe051TRGYKlZSx3
         9SD5RRx+FvjOewHowVtSQm574LKQgXJr+YSi+i4VACKBejpSpICuZXC3BRrykmQ/oC8P
         N1Rl5iFDpbw3eWl62hk8sST63vJ+8FaeX19vK/141gd+gye/yX9LbKpgrFkN0WtG2Ajn
         U48w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=sYjTbdC6;
       spf=pass (google.com: domain of rppt@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=rppt@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OryZFhlF9JPSZV1QJabqqsuJwfULKt8CZF5v4dRDV24=;
        b=bBIr5bGfAjyfTJr6mk2w21q4CIyOnqHz4AG9Gjen/fgUePUAJAlboHq5AKhClbktbQ
         sEOs4061PhxjOaKC/zWQVqOjmimwTo3Mb6UzypPD2VZpJWiERMELCJT6A4WvYR88L2JM
         0o2H3Np7FdtxIjZFru73+EM7DU80Rps+8Yj/z5TLJDn80o0rKvIGO308RHVd/WUzKcgx
         6gx1x4sFFbpzH/CNOuB1JzFhlcuwtIIZ/lkeVMD8cjef8vWe19Up3tgh6LnWa4EZhtPB
         shcyaIeBdx1V5+JWpZEijP6rqSDZYQ2HdK5NtmJKPfjRXjONpx1WF7IIoVVk7pooyua/
         6H4w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OryZFhlF9JPSZV1QJabqqsuJwfULKt8CZF5v4dRDV24=;
        b=bT5H8TEtTeLayhlF1E28Uo3S6b8QqwL9A77IL8EJ1haIyFCqAaELQ6AN9kRqO99rxN
         nJHHscfIeY68I9aATrjUftw3Mx6m0K0Vk7zThAX1sSCrTXE//YKED3wyfCi2t2Wz7T1G
         coYb7PCOMKz8AuhyUqpSs7lvTDi7xVLrkgyRP9j1bCf1lKXtpEbofmv19ATWX/fGNwF6
         rJOpMj20HOhYEgYELnX4LvqeGDp+119H5ooxg4KHskswC0r438HOw0eh0NyzPZf/ym4s
         XRXCxAXpaWBPIakIBeLqn2ReYW3OTXORy41DV+zz52BvTkJb9KBFsjtB4/jfeOzA2F48
         k3OQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532hU+QU3P1dTjpMgLgRKWzTDxR7ELKnm5U7wf9LW2w4fxGdUn/s
	9gBrgRsWUgbU4jlilHTiM6Q=
X-Google-Smtp-Source: ABdhPJzIKbdiPNGtxNfKd9V0HRq1n1p5B/sG+q53D3lyhpHK+L4gQStXCRUe6dl3GF/gx/1CsOYkhQ==
X-Received: by 2002:a9d:53c4:: with SMTP id i4mr24832768oth.79.1614163100036;
        Wed, 24 Feb 2021 02:38:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:2048:: with SMTP id f8ls502644otp.2.gmail; Wed, 24
 Feb 2021 02:38:19 -0800 (PST)
X-Received: by 2002:a05:6830:2148:: with SMTP id r8mr4713471otd.119.1614163099653;
        Wed, 24 Feb 2021 02:38:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614163099; cv=none;
        d=google.com; s=arc-20160816;
        b=szwHlNWtgJ6xM9oQngyir+wrVldeURB72Cji8yVoFI67Bd5043+Se4rcdwfIZDd89e
         j1Qq/c5behRErqf6ixbAbqOnhFNSR7ThQr3bDvWYpyDuEmY0adBTbQyQRiQkPCdYpCRy
         FY15MBf5clPIZnJhqBREJMjSSE27kDiJw4yVR2V7lGPpbHsiLM9FK4qdW/pdn+FZtLQw
         nt1OeOgVJe59KaB6/Ys2fMQXlR2f5iZQGHoZ6m5iWuwvo2WQjYydlOSsPSQxbYCFhXWk
         5sfrD5z3Unhj7ckPKI3LIny6iDG5fyTdxGMejW2xT1F5jgYtpxqC1y1lh2QaqvaCjitv
         yEtA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=8xs4x94E8tP06a4TxOYSjwpuKd4KODHK18iSUhK3G5s=;
        b=0Yt9ol2RbjwGT8JC6MuYU40/RjSQChs68uu0M+hddUxdDMhAF57bLL3VYsr3yRzsd1
         DwDmMfz7BNHVyNRgBQO8ggdffzYP64Elb8iDLl/67/ah+dFla4lCFGJdRdJe17JVWTZ7
         wesHCxznFlcfR6sQvBDBXpWnT17BBAKSKHFcfR2RBN3E//1YpmbEI0P4FEB+qM/gykSm
         c3IxZKPMnaAeg6pVFDUH4EkCG++m/9DieC/IRfHuXQjT2jYYTLiDvIPL6K6bID3Jlafg
         I0zKhrEy+EZlFpsOql5Dggk/3NTSaRweX8Rdg6ruepjCAw1JfUrMWmREALbELjCzVo/R
         BbkA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=sYjTbdC6;
       spf=pass (google.com: domain of rppt@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=rppt@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id n12si91314oie.2.2021.02.24.02.38.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 24 Feb 2021 02:38:19 -0800 (PST)
Received-SPF: pass (google.com: domain of rppt@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0098393.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.16.0.43/8.16.0.43) with SMTP id 11OAX4RB050234;
	Wed, 24 Feb 2021 05:38:05 -0500
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com with ESMTP id 36wmmf1680-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 24 Feb 2021 05:38:05 -0500
Received: from m0098393.ppops.net (m0098393.ppops.net [127.0.0.1])
	by pps.reinject (8.16.0.43/8.16.0.43) with SMTP id 11OAY9FQ059077;
	Wed, 24 Feb 2021 05:38:04 -0500
Received: from ppma01fra.de.ibm.com (46.49.7a9f.ip4.static.sl-reverse.com [159.122.73.70])
	by mx0a-001b2d01.pphosted.com with ESMTP id 36wmmf166c-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 24 Feb 2021 05:38:04 -0500
Received: from pps.filterd (ppma01fra.de.ibm.com [127.0.0.1])
	by ppma01fra.de.ibm.com (8.16.0.42/8.16.0.42) with SMTP id 11OAXMrf032178;
	Wed, 24 Feb 2021 10:38:01 GMT
Received: from b06avi18626390.portsmouth.uk.ibm.com (b06avi18626390.portsmouth.uk.ibm.com [9.149.26.192])
	by ppma01fra.de.ibm.com with ESMTP id 36tt289tcr-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 24 Feb 2021 10:38:00 +0000
Received: from d06av21.portsmouth.uk.ibm.com (d06av21.portsmouth.uk.ibm.com [9.149.105.232])
	by b06avi18626390.portsmouth.uk.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 11OAbjHH34537792
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 24 Feb 2021 10:37:46 GMT
Received: from d06av21.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id A07CC52050;
	Wed, 24 Feb 2021 10:37:58 +0000 (GMT)
Received: from linux.ibm.com (unknown [9.145.51.238])
	by d06av21.portsmouth.uk.ibm.com (Postfix) with ESMTPS id 5936852051;
	Wed, 24 Feb 2021 10:37:56 +0000 (GMT)
Date: Wed, 24 Feb 2021 12:37:54 +0200
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
Message-ID: <20210224103754.GA1854360@linux.ibm.com>
References: <20210222215502.GB1741768@linux.ibm.com>
 <9773282a-2854-25a4-9faa-9da5dd34e371@oracle.com>
 <20210223103321.GD1741768@linux.ibm.com>
 <3ef9892f-d657-207f-d4cf-111f98dcb55c@oracle.com>
 <20210223154758.GF1741768@linux.ibm.com>
 <3a56ba38-ce91-63a6-b57c-f1726aa1b76e@oracle.com>
 <20210223200914.GH1741768@linux.ibm.com>
 <af06267d-00cd-d4e0-1985-b06ce7c993a3@oracle.com>
 <20210223213237.GI1741768@linux.ibm.com>
 <450a9895-a2b4-d11b-97ca-1bd33d5308d4@oracle.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <450a9895-a2b4-d11b-97ca-1bd33d5308d4@oracle.com>
X-TM-AS-GCONF: 00
X-Proofpoint-Virus-Version: vendor=fsecure engine=2.50.10434:6.0.369,18.0.761
 definitions=2021-02-24_03:2021-02-24,2021-02-24 signatures=0
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 suspectscore=0 mlxscore=0
 spamscore=0 priorityscore=1501 bulkscore=0 clxscore=1015 phishscore=0
 mlxlogscore=999 impostorscore=0 lowpriorityscore=0 malwarescore=0
 adultscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2009150000 definitions=main-2102240081
X-Original-Sender: rppt@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=sYjTbdC6;       spf=pass (google.com:
 domain of rppt@linux.ibm.com designates 148.163.156.1 as permitted sender)
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

On Tue, Feb 23, 2021 at 04:46:28PM -0500, George Kennedy wrote:
>=20
> Mike,
>=20
> Still no luck.
>=20
> [=C2=A0=C2=A0 30.193723] iscsi: registered transport (iser)
> [=C2=A0=C2=A0 30.195970] iBFT detected.
> [=C2=A0=C2=A0 30.196571] BUG: unable to handle page fault for address: ff=
ffffffff240004

Hmm, we cannot set ibft_addr to early pointer to the ACPI table.
Let's try something more disruptive and move the reservation back to
iscsi_ibft_find.c.

diff --git a/arch/x86/kernel/acpi/boot.c b/arch/x86/kernel/acpi/boot.c
index 7bdc0239a943..c118dd54a747 100644
--- a/arch/x86/kernel/acpi/boot.c
+++ b/arch/x86/kernel/acpi/boot.c
@@ -1551,6 +1551,7 @@ void __init acpi_boot_table_init(void)
 	if (acpi_disabled)
 		return;
=20
+#if 0
 	/*
 	 * Initialize the ACPI boot-time table parser.
 	 */
@@ -1558,6 +1559,7 @@ void __init acpi_boot_table_init(void)
 		disable_acpi();
 		return;
 	}
+#endif
=20
 	acpi_table_parse(ACPI_SIG_BOOT, acpi_parse_sbf);
=20
diff --git a/arch/x86/kernel/setup.c b/arch/x86/kernel/setup.c
index d883176ef2ce..c615ce96c9a2 100644
--- a/arch/x86/kernel/setup.c
+++ b/arch/x86/kernel/setup.c
@@ -570,16 +570,6 @@ void __init reserve_standard_io_resources(void)
=20
 }
=20
-static __init void reserve_ibft_region(void)
-{
-	unsigned long addr, size =3D 0;
-
-	addr =3D find_ibft_region(&size);
-
-	if (size)
-		memblock_reserve(addr, size);
-}
-
 static bool __init snb_gfx_workaround_needed(void)
 {
 #ifdef CONFIG_PCI
@@ -1032,6 +1022,12 @@ void __init setup_arch(char **cmdline_p)
 	 */
 	find_smp_config();
=20
+	/*
+	 * Initialize the ACPI boot-time table parser.
+	 */
+	if (acpi_table_init())
+		disable_acpi();
+
 	reserve_ibft_region();
=20
 	early_alloc_pgt_buf();
diff --git a/drivers/firmware/iscsi_ibft_find.c b/drivers/firmware/iscsi_ib=
ft_find.c
index 64bb94523281..01be513843d6 100644
--- a/drivers/firmware/iscsi_ibft_find.c
+++ b/drivers/firmware/iscsi_ibft_find.c
@@ -47,7 +47,25 @@ static const struct {
 #define VGA_MEM 0xA0000 /* VGA buffer */
 #define VGA_SIZE 0x20000 /* 128kB */
=20
-static int __init find_ibft_in_mem(void)
+static void __init *acpi_find_ibft_region(void)
+{
+	int i;
+	struct acpi_table_header *table =3D NULL;
+	acpi_status status;
+
+	if (acpi_disabled)
+		return NULL;
+
+	for (i =3D 0; i < ARRAY_SIZE(ibft_signs) && !ibft_addr; i++) {
+		status =3D acpi_get_table(ibft_signs[i].sign, 0, &table);
+		if (ACPI_SUCCESS(status))
+			return table;
+	}
+
+	return NULL;
+}
+
+static void __init *find_ibft_in_mem(void)
 {
 	unsigned long pos;
 	unsigned int len =3D 0;
@@ -70,35 +88,44 @@ static int __init find_ibft_in_mem(void)
 				/* if the length of the table extends past 1M,
 				 * the table cannot be valid. */
 				if (pos + len <=3D (IBFT_END-1)) {
-					ibft_addr =3D (struct acpi_table_ibft *)virt;
 					pr_info("iBFT found at 0x%lx.\n", pos);
-					goto done;
+					return virt;
 				}
 			}
 		}
 	}
-done:
-	return len;
+
+	return NULL;
 }
+
+static void __init *find_ibft(void)
+{
+	/* iBFT 1.03 section 1.4.3.1 mandates that UEFI machines will
+	 * only use ACPI for this */
+	if (!efi_enabled(EFI_BOOT))
+		return find_ibft_in_mem();
+	else
+		return acpi_find_ibft_region();
+}
+
 /*
  * Routine used to find the iSCSI Boot Format Table. The logical
  * kernel address is set in the ibft_addr global variable.
  */
-unsigned long __init find_ibft_region(unsigned long *sizep)
+void __init reserve_ibft_region(void)
 {
-	ibft_addr =3D NULL;
+	struct acpi_table_ibft *table;
+	unsigned long size;
=20
-	/* iBFT 1.03 section 1.4.3.1 mandates that UEFI machines will
-	 * only use ACPI for this */
+	table =3D find_ibft();
+	if (!table)
+		return;
=20
-	if (!efi_enabled(EFI_BOOT))
-		find_ibft_in_mem();
-
-	if (ibft_addr) {
-		*sizep =3D PAGE_ALIGN(ibft_addr->header.length);
-		return (u64)virt_to_phys(ibft_addr);
-	}
+	size =3D PAGE_ALIGN(table->header.length);
+	memblock_reserve(virt_to_phys(table), size);
=20
-	*sizep =3D 0;
-	return 0;
+	if (efi_enabled(EFI_BOOT))
+		acpi_put_table(&table->header);
+	else
+		ibft_addr =3D table;
 }
diff --git a/include/linux/iscsi_ibft.h b/include/linux/iscsi_ibft.h
index b7b45ca82bea..da813c891990 100644
--- a/include/linux/iscsi_ibft.h
+++ b/include/linux/iscsi_ibft.h
@@ -26,13 +26,9 @@ extern struct acpi_table_ibft *ibft_addr;
  * mapped address is set in the ibft_addr variable.
  */
 #ifdef CONFIG_ISCSI_IBFT_FIND
-unsigned long find_ibft_region(unsigned long *sizep);
+void reserve_ibft_region(void);
 #else
-static inline unsigned long find_ibft_region(unsigned long *sizep)
-{
-	*sizep =3D 0;
-	return 0;
-}
+static inline void reserve_ibft_region(void) {}
 #endif
=20
 #endif /* ISCSI_IBFT_H */

--=20
Sincerely yours,
Mike.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20210224103754.GA1854360%40linux.ibm.com.
