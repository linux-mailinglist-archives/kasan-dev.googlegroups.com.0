Return-Path: <kasan-dev+bncBD4O7ZP764ERBT4MVL7AKGQE3MRA3GQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 9E61A2CF46D
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Dec 2020 19:56:16 +0100 (CET)
Received: by mail-pg1-x53c.google.com with SMTP id 1sf4091734pgq.11
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Dec 2020 10:56:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607108175; cv=pass;
        d=google.com; s=arc-20160816;
        b=AoJ2/1/DR9X8f+Jov/0Qru4NTviiNWqN+gEkVpMK/SPHrLpJeaD6uJK6GAQj8zaH+4
         oJLOu6RnOksvQemEhTWWSe4jlP2s8Ek+8yjzDdazk8Qe8PABTRDcSUPTlEq2oauyxdQa
         wqCb+UwXy13HbAlK5CPujaqrQr68JCoHaizELCziZ38mLxybv/e4puERr93lHRvMTLOv
         JXtqhVFzRyd2p/U7pzIMWwaJ/0dwJ/2FW96H7PW1L9tCHupqlsV1DyZymr6UOWhDfQoS
         rElHEqjsuOCIQEGOVxdWmDTuy4SiH3MkMBf6LQOAoXgM/Lx3g5tz+e77UVSKE6FseoXc
         PL8w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:date:cc:to
         :from:subject:message-id:sender:dkim-signature;
        bh=zEDQJf8W9J1acanMVrUQxrMTGoCXCmQRrKz4Frt5K5w=;
        b=vBVEsiklcBcYdkvSlpOGq9XE6Te0A8ba54nehTh5EzsnJcuu37aBb2HP8nqcwY1LWJ
         hXZLXpkIae8rr2QG/wLQJqxaOf+mENH0rCkpBvE+EWTbFxKWrW4vNK7BbPW13m3HLkW4
         8vyI1+XPeTgpX4B3Chn6zQZw1S/QsVaCxLK1KT/eeDUe3PZuoHgQNosgnY80uWNN71Pe
         ysZmA9aW4cfWrXnHg5hzVZPNB18HZK7ykSWwAn3NZLUnAlMsIK4MAg+L0Bll4uaIA59n
         Q5MFx/TyBz4Zv3navtt3FYWhOFtOYy44NWDyzSkQNXHWP79Rm+dLMOxfauRwcKB9I6qh
         ZEyA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rajagiritech-edu-in.20150623.gappssmtp.com header.s=20150623 header.b=jlWQjTCA;
       spf=neutral (google.com: 2607:f8b0:4864:20::62a is neither permitted nor denied by best guess record for domain of jeffrin@rajagiritech.edu.in) smtp.mailfrom=jeffrin@rajagiritech.edu.in
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:user-agent:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zEDQJf8W9J1acanMVrUQxrMTGoCXCmQRrKz4Frt5K5w=;
        b=kduCGI/6zP0ddvGnowsvoHq1Fi0DCOLY5ok1bDUVMpmUE7roXURij8HbZypXWJQmm2
         q3Ar4jvO7FdNaWP7XAqpi5xcTtfbUJPjmjyxhyEHWx5uBUqgOj0M325o14dY6SEKvJOl
         szqMms/ZAPbSAWIDBPUCY2VtxpJVVlSWh0d+4flHpdX9LfBgmq36gXlsMMlOhdQiDxY0
         1beA4PXBpuk4oW//4poYp12P98MvZ4xJN3ayne0mr3J/pT4w5wyDtDwGL+DFMWDR7JJm
         W+8Jjs9LORjmgDUfUbRa/OA2K9eVF8BC5lqod0oue/4lDh4O8Gc/SQHppGtEimgK+7Ff
         8flQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zEDQJf8W9J1acanMVrUQxrMTGoCXCmQRrKz4Frt5K5w=;
        b=KENcs5yb/iGe4kBUfeAO5RABCJxq5sSvNZ/XsY9PMM21c5YPmGrkQEJ15Ugnok8vrS
         A93NKQ3ETdYGvNI3MxwZwth76DCDN9p2mYg1Ez1+Z7LlRs9Hvdko9fsrKhZCu4SamGND
         x2LZZkAOembExi/FDbsXxQje8KYzutJYJQHBHoS+nixPYn2Vf6lPsVyNV53YePm6i6/K
         g+ZkBRfN/z40FCF67yAOMwTXxSZu44QW5cxWV9r4xmeSxWqj08mKT4yO/nK4/j5+lI1y
         YKt56y3fpg2PYwYBNpvUg2ny7afX9JA3p7AD6yD0H/YUaekrsuaBU/D68cZEnHU/S+sR
         eO0Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530kfbaURE5CxLjld1mvCqJDh1x7TXVUosnz2CJ+hlsyKkPGuZ7G
	iK6LAdydhz/6kbo21svgSNI=
X-Google-Smtp-Source: ABdhPJz3sT/sYAryzYnZCS1H9EQcIRXDCdt2rLeppxSeODvZuKc32UKN7BPdGvEQ0OVi4mlvnV/SbA==
X-Received: by 2002:a17:90b:614:: with SMTP id gb20mr5453724pjb.34.1607108175314;
        Fri, 04 Dec 2020 10:56:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:f0f:: with SMTP id br15ls5395851pjb.3.canary-gmail;
 Fri, 04 Dec 2020 10:56:14 -0800 (PST)
X-Received: by 2002:a17:90a:5d0e:: with SMTP id s14mr5458125pji.53.1607108174803;
        Fri, 04 Dec 2020 10:56:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607108174; cv=none;
        d=google.com; s=arc-20160816;
        b=lWdYODT5e7Ekhgrbx+IHrQb/aCjsTSGlDULQZr7Jy9Rkk4OFkWaKG7hRxlyIehBcLs
         sjHy02WqcVqFktjPzn1c4E/rwd55pIEMslCdmUR86mTBMJZm4frfoyh//9B7L8N2NuLv
         pL6xL2MF0aFW6z91klcah5jgFLvxyRADWYojd4qj81SoBHi/4F5yGgJV/Gv3v52Ialkr
         laYWr66R2bTWsSkl3KRc8G3o6mWMHCu+TLrN7WDAV5gHcNrKDBdZL0N6DvKOPI9t3bY4
         SrwEcZ1s7805lv5KDeaKDozaYUaMIBO9xrlxiARIm4F5YWAVxQqNXvSJyCQ9UD/L6E07
         88Fw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:user-agent:date:cc:to:from
         :subject:message-id:dkim-signature;
        bh=BabgtABiUfhimEJA8On2IJzMRIuNBST9b1rkNpp1/zM=;
        b=xmPj9oSbIOwh0T5Wx3l08KaYXyH96jcVmO/7tEKhtiTN5lTlf2oQ1N/mVeNABMO8iE
         OVtpQcvsFS8hP2jN/zmYGNY0pxPFAo2OTYlo+vXrczzf/xVMX9keFAza6iYA+T6N4vo1
         FRG5R/i9ICw5YNMIA/2EHcuGXuSZ1m4RGu7U3M2PK2dVvvMWfCN/X/e2rnE/9V/BQ40Y
         U1c5OEocfcVQUumdfSwMyAt8v8SbLGiFF1FHRJ1VZDfWbnRl711Qh+rhVfD2nqybCid7
         J3diBk2XrVwZ4WYqO/mzShTlKlBVq9bY08yxQgKO+2JziHkPm4ubzymPKmMCHwN4izhX
         j5Lw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rajagiritech-edu-in.20150623.gappssmtp.com header.s=20150623 header.b=jlWQjTCA;
       spf=neutral (google.com: 2607:f8b0:4864:20::62a is neither permitted nor denied by best guess record for domain of jeffrin@rajagiritech.edu.in) smtp.mailfrom=jeffrin@rajagiritech.edu.in
Received: from mail-pl1-x62a.google.com (mail-pl1-x62a.google.com. [2607:f8b0:4864:20::62a])
        by gmr-mx.google.com with ESMTPS id c17si403764pls.3.2020.12.04.10.56.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 04 Dec 2020 10:56:14 -0800 (PST)
Received-SPF: neutral (google.com: 2607:f8b0:4864:20::62a is neither permitted nor denied by best guess record for domain of jeffrin@rajagiritech.edu.in) client-ip=2607:f8b0:4864:20::62a;
Received: by mail-pl1-x62a.google.com with SMTP id j1so3640771pld.3
        for <kasan-dev@googlegroups.com>; Fri, 04 Dec 2020 10:56:14 -0800 (PST)
X-Received: by 2002:a17:902:ee52:b029:da:4dee:1a54 with SMTP id 18-20020a170902ee52b02900da4dee1a54mr5030102plo.29.1607108174434;
        Fri, 04 Dec 2020 10:56:14 -0800 (PST)
Received: from [192.168.1.9] ([122.164.27.91])
        by smtp.gmail.com with ESMTPSA id d4sm2833964pjz.28.2020.12.04.10.56.12
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 04 Dec 2020 10:56:13 -0800 (PST)
Message-ID: <dc46ab93e6b08fa6168591c7f6345b9dc91a81bb.camel@rajagiritech.edu.in>
Subject: BUG: KASAN   lib/test_kasan.c
From: Jeffrin Jose T <jeffrin@rajagiritech.edu.in>
To: aryabinin@virtuozzo.com, Alexander Potapenko <glider@google.com>, Dmitry
	Vyukov <dvyukov@google.com>
Cc: kasan-dev@googlegroups.com, lkml <linux-kernel@vger.kernel.org>
Date: Sat, 05 Dec 2020 00:26:10 +0530
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.38.1-2
MIME-Version: 1.0
X-Original-Sender: jeffrin@rajagiritech.edu.in
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rajagiritech-edu-in.20150623.gappssmtp.com header.s=20150623
 header.b=jlWQjTCA;       spf=neutral (google.com: 2607:f8b0:4864:20::62a is
 neither permitted nor denied by best guess record for domain of
 jeffrin@rajagiritech.edu.in) smtp.mailfrom=jeffrin@rajagiritech.edu.in
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

hello,

 detected   KASAN   BUG

[ related information ]

-------------------x-------------------x------------------------>
[   43.616259] BUG: KASAN: vmalloc-out-of-bounds in
vmalloc_oob+0x146/0x2c0

(gdb) l *vmalloc_oob+0x146/0x2c0
0xffffffff81b8b0b0 is in vmalloc_oob (lib/test_kasan.c:764).
759		kfree_sensitive(ptr);
760		KUNIT_EXPECT_KASAN_FAIL(test, kfree_sensitive(ptr));
761	}
762	
763	static void vmalloc_oob(struct kunit *test)
764	{
765		void *area;
766	
767		if (!IS_ENABLED(CONFIG_KASAN_VMALLOC)) {
768			kunit_info(test, "CONFIG_KASAN_VMALLOC is not
enabled.");
(gdb) l *vmalloc_oob+0x146
0xffffffff81b8b1f6 is in vmalloc_oob (lib/test_kasan.c:779).
774		 * The MMU will catch that and crash us.
775		 */
776		area = vmalloc(3000);
777		KUNIT_ASSERT_NOT_ERR_OR_NULL(test, area);
778	
779		KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char
*)area)[3100]);
780		vfree(area);
781	}
782	
783	static struct kunit_case kasan_kunit_test_cases[] = {
----------------x-----------------------------x-------------------->

Reported by: Jeffrin Jose T <jeffrin@rajagiritech.edu.in>

-- 
software engineer
rajagiri school of engineering and technology - autonomous


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/dc46ab93e6b08fa6168591c7f6345b9dc91a81bb.camel%40rajagiritech.edu.in.
