Return-Path: <kasan-dev+bncBCYIJU5JTINRBEE3W2XAMGQE32U6VIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3a.google.com (mail-io1-xd3a.google.com [IPv6:2607:f8b0:4864:20::d3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 4C58385599C
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Feb 2024 05:05:38 +0100 (CET)
Received: by mail-io1-xd3a.google.com with SMTP id ca18e2360f4ac-7baa66ebd17sf46136639f.1
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Feb 2024 20:05:38 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1707969936; cv=pass;
        d=google.com; s=arc-20160816;
        b=agfl0AXxfPKZq9Gi+DKvFaySAGxRrKiQIPV09+A/Chr0tQfJrwU5MKDdJPnoD3s8mq
         l1dtjQ8Jb9I3/yT0BCXn/yU4sXEWAqN3W10scY9w5qhLZSquKLMFZfF7JOYE3EDZZ2UD
         rJt8Sd+1y2AsakDTvRqydsCqCUirX7LwEZrX3Vay6N4yA+V+Lk3NqckmSa+UV2KnSBDF
         0fttVdFZjD0NaSy7UGHXMH4Z/a9/WRdkLu6pvt3xXyu+nv+2IY4qsfdKmeMojUeA1QAq
         SS9KB1CKxzIUe5WfBdXm2eEePiiFCP8auvjII3v4dzb8RrP02FboMBaOemD8EQE5tM/J
         FGGg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:in-reply-to
         :content-disposition:references:mail-followup-to:message-id:subject
         :cc:to:from:date:sender:dkim-signature;
        bh=pORI4ScEjdKWS5DKBGaiIiOltTE6+RsH2/R5CpLuZ6E=;
        fh=r7SBz2KpAomAkxc6tvLtCEJzFwoCnSCCGI2ZbfhCNSk=;
        b=regEjmaZSELw79M9/YFDLmu+/X+Sf4iy3UZkR/DoGVViTAUJ8oUcOcvXP5DTwE+y1R
         sLZaddyElGpx3eO4w0TFUZt9kZcnjNRUumWhixFtW4FifXQfZ6qf0WSmzHr/4a2mPnd2
         qDRN92PFNLvlnGCQzvvuEDtYuV7yQphfuYzQuPP8x8AGHKV9bHOPk1suzYTrw3nYAET8
         rhplJ/UOQXihoAsz+tphlkCoYDV04jY9NXtxxMhRbrc5exfzQdpDISXhuxic8Cjdlfc+
         6kbC6AFj81NNyGIyjPZ6KnX7cGRikQ+4ZqaWSSZIpEFIGjGkiQtEUt1HnOcv0dVCUusG
         aasA==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2023-11-20 header.b=T1mUc4c7;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=DIzThlLr;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of liam.howlett@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=liam.howlett@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707969936; x=1708574736; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:in-reply-to
         :content-disposition:references:mail-followup-to:message-id:subject
         :cc:to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=pORI4ScEjdKWS5DKBGaiIiOltTE6+RsH2/R5CpLuZ6E=;
        b=Z/IdlMqjTan0mE9nPewRdV0xEXGc42ce0kCjutSIgRCp2yc/+Wc2DimpK+Ph/954JM
         CtODswoQpP7BZxyX4C8M6/FZbaHoqDg2qGwdFKR5RCIRouICdmoltxo3O3QNf40wxKzr
         jXqVMU1M/nXY92mBZvKPRWNUm7tUhmpqCaFqx370fcPbTLPOgwbX0xjEKejnl06n6Z6g
         zEttay9Pc2USzZ8UMST8S8Sy/xmzQ/EAAZdjBsaX0uOEP3v+kS3IN0aEqkp1rU60gOX8
         +IP7WXb05RQvJRX2kvYHLEhZ1YQe4YyJdlr+czuaTfd+I8g2n/O1LyWr+uhjJUA1Cd/1
         /1tg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707969936; x=1708574736;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:in-reply-to:content-disposition:references
         :mail-followup-to:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=pORI4ScEjdKWS5DKBGaiIiOltTE6+RsH2/R5CpLuZ6E=;
        b=j/5bzPvGC9sXng8NC7YbSxvyhEPhzvIAjk79tXtT/FLbfaNlk36C+7XR5yNSjEo5TA
         N7/s/Y+AkkuYnt/xDV7b3DWUUxwN5fg8i9BfFLvbhmCNZYgsPvnXKLpn8MORqDwkxDY3
         UJ9HSxLtp1c1FjsC4ffzTNjMvI4WZ3EbbIF8ZN1WFNsXVJs3T++b8fqSyUQFu/OCwHCb
         r0HbbaJg+LWAcFGtPaHyW6hBX7cKYOcrSgBq4KAwFybBNlvyypqYjgPHS/R6loc0FFgx
         hZOfN9UFLYCkvHnr0dK7TwvRCPzi7s96QTfw56Me3wfADwNYuUOtgeUwF8oQGsAhG/91
         qxbA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=3; AJvYcCVdZdeVSshHjvZw31zNTIsZvlpD0CWomwaOnY0210Fz/Kz9RkVW9AJwzSsAXZ7HlbR56KXM8dP2E4nSrBfARBa2dHe8OiD0AA==
X-Gm-Message-State: AOJu0Ywc98hVs/blL0ookSfabwEPnHXdjf4MxbBi/BR/g49ZVsVKgvHu
	BaPB+JxXU5MK8cagqvd1I2LdbBB1Vzw1A/qDJWPLqZ14D9cAgfFs
X-Google-Smtp-Source: AGHT+IELe779IKDRSLjoY9ajKd7SbPEFwaf+UhkwWfbGsen/9m2oBA9JQiDBkmz6vv/kVzfFMVzi2w==
X-Received: by 2002:a05:6e02:13c8:b0:363:d734:14b with SMTP id v8-20020a056e0213c800b00363d734014bmr559055ilj.26.1707969936669;
        Wed, 14 Feb 2024 20:05:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:3881:b0:363:8ef4:5a96 with SMTP id
 cn1-20020a056e02388100b003638ef45a96ls1957735ilb.2.-pod-prod-09-us; Wed, 14
 Feb 2024 20:05:35 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCUCrZs8ezEXxzJRGz6F+ASTuITDxqdPUj+aw6HKnr1J37GmX965DXY7PATAKh/BCERc5fL7XoNqs0i7yEX2FCJ1QMxi5TCGjR0Sfg==
X-Received: by 2002:a6b:ca81:0:b0:7bf:d163:1e96 with SMTP id a123-20020a6bca81000000b007bfd1631e96mr945525iog.6.1707969935609;
        Wed, 14 Feb 2024 20:05:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707969935; cv=pass;
        d=google.com; s=arc-20160816;
        b=fi0YV+xfvPQC2NpWMSAvamUK1hVR/Z0L7xiDgT9//EhV7oAvLX5XFbE7zaIDECQG+r
         PqZcNl3qj8zVc1GxmT78fLOJyVvYY1HiPC/UmqKD3BfqSzQX11j706GAi8MbS0otfjUz
         ffWtujPCya6r8ubbLR8gxc0KX6/fG6oGVxBHqJ9JyMvRVzS/9ssulQr/KyK9zTQVv3Fs
         bBrUIOK5GBQkQEDc6Wx3QjVeZl6n81lar02LYNaMQfftEBQMXJ96rskbNiJIsb2bZket
         xNE9E5bhM0W0ep9XZv+oyy+cIEMnZstl/5C2hw/l7VhEUUCWDI95F3pmKNx4L8Y8y+D8
         JNMQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:in-reply-to:content-disposition:references
         :mail-followup-to:message-id:subject:cc:to:from:date:dkim-signature
         :dkim-signature;
        bh=kaDunI3VrU2cmdOrW2tuKgCd/NNFeW2a92BirTflQTY=;
        fh=Hl7kl7hkJuaWdMYT65MW9KDeT8S5EqJ2C0geCnFaP7A=;
        b=y/FTORwnqdvGiVqDlbNAUd+CKCgVqhA/GxDy1lu4esH2jDOS+YNKC3U39zdLR9veA9
         vFKhOH688k/52pcCtASim43uXo7HyrfVBmXwe4Cpsh9AnPq/H17oOvJfvN/HL+GN27SR
         0frxhVWp0JPxKHyUCIfKQDfn3dbmVqbTpwmJHvnteKZEPBGbXCnpChjynBvj/DkWxXMG
         27YMypAIvsZzLIRf6sYcFIKBjh9FrRAVeq2cjl8tSWIjXgRisKvMCJsA97Xrv29xAZW+
         IrE6RMkPtcepAHG4Pm0iV77LzCVYh8wS4mjIKQELlxSEINOA1e3p2U31uuGorWDbjZk6
         laug==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2023-11-20 header.b=T1mUc4c7;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=DIzThlLr;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of liam.howlett@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=liam.howlett@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id b14-20020a056602274e00b007c3f8360af9si16823ioe.0.2024.02.14.20.05.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 14 Feb 2024 20:05:35 -0800 (PST)
Received-SPF: pass (google.com: domain of liam.howlett@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0246632.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 41EMhtG3007312;
	Thu, 15 Feb 2024 04:04:57 GMT
Received: from iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta03.appoci.oracle.com [130.35.103.27])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 3w92j0gxfj-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 15 Feb 2024 04:04:56 +0000
Received: from pps.filterd (iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (8.17.1.19/8.17.1.19) with ESMTP id 41F20oUk031337;
	Thu, 15 Feb 2024 04:04:55 GMT
Received: from nam12-bn8-obe.outbound.protection.outlook.com (mail-bn8nam12lp2168.outbound.protection.outlook.com [104.47.55.168])
	by iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 3w5yk9w84h-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 15 Feb 2024 04:04:55 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=eU1/nOQ1EPFaWHEfGPII9WS4/krXvPiqPPdYmsZ6pbHZjx+ww7/jh+S3p+x8dIQBy+H+YQMHBCtRNuChbH/MgvqPTVm1ocGIyADDXGkljw5D/c6M6iYPeBBvrpc1lPGLhhM5CS3Vo93PVEFbkQyyWMps3YiOjGX32q3HwtVvDcPW4MM8nk5yYwiHPhCu2hriaJpZ7DUcWSD2P5hwY8mHECuVsCzb7sPQBGpshvZoY9LN22BWNxNC5eVXsP+j4cyDUU8qNyCe1Ig8BcNbNYAQNsmTSyhWqrHAe7YKNP4Wexe8S6/RiGElMs35SAL2C+F2n0Rz7CGmMji0rzYjcNXkZQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=kaDunI3VrU2cmdOrW2tuKgCd/NNFeW2a92BirTflQTY=;
 b=ERursZ2b7kwlkoV0sAHZor5MlBdtWuo14ueUgkcVQB1CJEcyGt50SYc76e0Uc7P67TzNEUt1tWvE4kZiIBys25xkVZKR7UeA3QZ7OcCocrLxPo37w6pp3YlF3BI1SYXy+8Ed3KtqQhKTjY3a7Ie5zZCKr8jANLLL52fGVp7hNDgQgq89f4bSJTlesU/UgycYkOYPV1RBZISixzBl93dSoEjYECfFTbwwfvly36MqAV6CmHdUTWec3DD5zASKZRdx/CEovjs37PnQGDVnsfFJzSVWvYwI8jL0qOZpfFE5JgJ3/sS4egNy6/bO7m++3ZUDLj1OB4Jz/iKxYQfNDW80pA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DS0PR10MB7933.namprd10.prod.outlook.com (2603:10b6:8:1b8::15)
 by BLAPR10MB5300.namprd10.prod.outlook.com (2603:10b6:208:334::13) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.7292.26; Thu, 15 Feb
 2024 04:04:53 +0000
Received: from DS0PR10MB7933.namprd10.prod.outlook.com
 ([fe80::20c8:7efa:f9a8:7606]) by DS0PR10MB7933.namprd10.prod.outlook.com
 ([fe80::20c8:7efa:f9a8:7606%4]) with mapi id 15.20.7270.033; Thu, 15 Feb 2024
 04:04:53 +0000
Date: Wed, 14 Feb 2024 23:04:48 -0500
From: "Liam R. Howlett" <Liam.Howlett@Oracle.com>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Kent Overstreet <kent.overstreet@linux.dev>,
        Kees Cook <keescook@chromium.org>,
        Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org,
        mhocko@suse.com, hannes@cmpxchg.org, roman.gushchin@linux.dev,
        mgorman@suse.de, dave@stgolabs.net, willy@infradead.org,
        corbet@lwn.net, void@manifault.com, peterz@infradead.org,
        juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org,
        arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com,
        dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com,
        david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org,
        masahiroy@kernel.org, nathan@kernel.org, dennis@kernel.org,
        tj@kernel.org, muchun.song@linux.dev, rppt@kernel.org,
        paulmck@kernel.org, pasha.tatashin@soleen.com, yosryahmed@google.com,
        yuzhao@google.com, dhowells@redhat.com, hughd@google.com,
        andreyknvl@gmail.com, ndesaulniers@google.com, vvvvvv@google.com,
        gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com,
        vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
        rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com,
        vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
        iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
        elver@google.com, dvyukov@google.com, shakeelb@google.com,
        songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com,
        minchan@google.com, kaleshsingh@google.com, kernel-team@android.com,
        linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
        iommu@lists.linux.dev, linux-arch@vger.kernel.org,
        linux-fsdevel@vger.kernel.org, linux-mm@kvack.org,
        linux-modules@vger.kernel.org, kasan-dev@googlegroups.com,
        cgroups@vger.kernel.org
Subject: Re: [PATCH v3 23/35] mm/slub: Mark slab_free_freelist_hook()
 __always_inline
Message-ID: <20240215040448.ycfrrqbv6chjeysy@revolver>
Mail-Followup-To: "Liam R. Howlett" <Liam.Howlett@Oracle.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	Kent Overstreet <kent.overstreet@linux.dev>,
	Kees Cook <keescook@chromium.org>,
	Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org,
	mhocko@suse.com, hannes@cmpxchg.org, roman.gushchin@linux.dev,
	mgorman@suse.de, dave@stgolabs.net, willy@infradead.org,
	corbet@lwn.net, void@manifault.com, peterz@infradead.org,
	juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org,
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com,
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com,
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org,
	masahiroy@kernel.org, nathan@kernel.org, dennis@kernel.org,
	tj@kernel.org, muchun.song@linux.dev, rppt@kernel.org,
	paulmck@kernel.org, pasha.tatashin@soleen.com,
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com,
	hughd@google.com, andreyknvl@gmail.com, ndesaulniers@google.com,
	vvvvvv@google.com, gregkh@linuxfoundation.org, ebiggers@google.com,
	ytcoode@gmail.com, vincent.guittot@linaro.org,
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com,
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com,
	penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com,
	glider@google.com, elver@google.com, dvyukov@google.com,
	shakeelb@google.com, songmuchun@bytedance.com, jbaron@akamai.com,
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com,
	kernel-team@android.com, linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev,
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org,
	linux-mm@kvack.org, linux-modules@vger.kernel.org,
	kasan-dev@googlegroups.com, cgroups@vger.kernel.org
References: <20240212213922.783301-1-surenb@google.com>
 <20240212213922.783301-24-surenb@google.com>
 <202402121631.5954CFB@keescook>
 <3xhfgmrlktq55aggiy2beupy6hby33voxl65hqqxz55tivdbbi@j66oaehpauhz>
 <6370b20f-96fb-4918-bef0-7555563c9ce2@suse.cz>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <6370b20f-96fb-4918-bef0-7555563c9ce2@suse.cz>
User-Agent: NeoMutt/20220429
X-ClientProxiedBy: YT3PR01CA0057.CANPRD01.PROD.OUTLOOK.COM
 (2603:10b6:b01:82::27) To DS0PR10MB7933.namprd10.prod.outlook.com
 (2603:10b6:8:1b8::15)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DS0PR10MB7933:EE_|BLAPR10MB5300:EE_
X-MS-Office365-Filtering-Correlation-Id: 800219b6-fba5-47d2-f819-08dc2ddb432c
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: NfptJ+x0bObDNfmoPwJFZpbn/Y1uejx2NbqeelCsw07/d0O69rkk59da8Z3xj5qZCw63JhpW5XLxdXIwnkv9vB+z9wmdtzAP0LcVO0+gOg1cSDV88c6v9/EyDWzsL6Kbc8E399yPw1J1oK2IkOmDmTjFekCMAKAwtO7M21oDOlq7oEVtKMvsRjkYnYeDMKFhToetMxA9ROfQTnsk5eNpHwRhN8LUoRttTNDv25lkJJwP8p+1OOoh9tpFIL7GLC8eYnn+VTG0PwPWi3EqowvKdOigcEqWYIrTJB3bzTrqOtuOADmDhiyu7xPciGuqvuYI4npcqQ4mqs7z9yiLrKqzIrseXuuN4CgvSRKLXuB/Z+gR2BkFBdg8kr/sys86IrkhGu81xnw5tFVzuhsEGbj6dctHbhbv44i/cGE+hVGWmrTT4PNbzwrMk3nTjI0JOjiJDWPxyFn+mHKb8q/76TS8BtT/DXdE5/6PAR+C7j9rAB+2dBxlKgSAbRuaOUMG6WgTiraViPBpAp5mJAZfprpj/2X31chF/DzgFpgIKMmg0KKCiL7Rk2Tzeu0IN+5tD+tf
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DS0PR10MB7933.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230031)(7916004)(396003)(39860400002)(366004)(136003)(376002)(346002)(230922051799003)(1800799012)(64100799003)(186009)(451199024)(86362001)(33716001)(8936002)(8676002)(5660300002)(66556008)(66946007)(66476007)(4326008)(7416002)(7366002)(7406005)(6916009)(6512007)(9686003)(6506007)(6486002)(478600001)(2906002)(1076003)(38100700002)(41300700001)(26005)(316002)(6666004)(53546011)(54906003);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?gYLFJ8fk4kEAKbBsM7PU3Fx9HcRMAOf2K2KfqiRVu5H2EXh656UVyGQD3AKX?=
 =?us-ascii?Q?QKZT+LYbYApmFNAaz5gqF1qw3zb5xHls+H/NgQz1JrpT6NomDnN+ZyESFMST?=
 =?us-ascii?Q?ULkjbEQcf8iaUmbxSTrCTo4QkQL18mG82T31tS5V4BndQCVVXHyPq5fM0tUq?=
 =?us-ascii?Q?jQELAio5VgSoGrPj1Wo1vg9uKup+LHeMXFjAJ2g+AcatwsLk9aHzaCdLIN21?=
 =?us-ascii?Q?fGK1KGKQCeFUL7lcGCPp8J7kFBCwdGr1OFymdoticBg7Pd6OGd1jQtEvtEhO?=
 =?us-ascii?Q?bj0/x/FNSBCe+FLAow0Ce7Cugh/Z9FMvxaO16nhxh9PGk7WevJiGFx1awQ7t?=
 =?us-ascii?Q?7U+Q76iR6f/e7uxTBB8iTGbccq6bWYzyGWJTYExoXfTHHQTjtBimCou5IoWx?=
 =?us-ascii?Q?ZhH7IzUXJhYy9jG29lgKQyKTrbPaCoXiMiqkXvKzCKA0O6SI5TBNYt0AQNbK?=
 =?us-ascii?Q?4vDX+ClVTZKIcbgefAoe6B54ja1lmFQN+Ys0QzS2fR+RNv2YmzVai1RvS1SP?=
 =?us-ascii?Q?/D+bH1gkvqJWojNwZSebG76nPNYlze1f/qqPOBhKX2aeDTzUjSP3SJ4lc/7y?=
 =?us-ascii?Q?xuGwL8HaNE9lPHwxjd2uHRC7Fhc2nL5Lmxh3I+JR9yEbOizgECoZ9g3Hl2DJ?=
 =?us-ascii?Q?xCr9FyrbegDB7WBHkQ8JNbBkMlYN4aLHO5aAfWEo2vq5GezDadI5peoULyO1?=
 =?us-ascii?Q?KJNUTNGA1ILG4tOvONpuoXNIisoEQKPrEZybVQ295s8KmEVexUpT5AaVKpm1?=
 =?us-ascii?Q?CMYYbv/5x5eazKxv7Seadg1kZ0FyBjkEFko/17Hr81/NMcHoH1SfM8cvr4uO?=
 =?us-ascii?Q?ftCSdkZpRXnNaA6vi8UuCfNyWOsGhrJC8sbwPm6OqZhwBm4Glalb1tT/UB7/?=
 =?us-ascii?Q?XJ97kPw24tm3BaVd6hXPzIZFkGrfCNywcmjU6u9j0qecXKPoMmiRlHgvt1XY?=
 =?us-ascii?Q?cP4fetV3C/t++XqhAwbeZ2q+zJ2sBb1xtuF//dPQlzC+vXjpMnc55TXTah0r?=
 =?us-ascii?Q?8+ZL4MZs+b/vpp6a94j/h6bMtJnW+CUuL1roJ3scaY/UQdsDVnCSoYdWa+zf?=
 =?us-ascii?Q?aIwWSU2niqj6NPyMv4I3IOffivp4IExwKwQ8dkRa78Tidy6bGv40oXctG5FK?=
 =?us-ascii?Q?OtYqxu91PgTt+KMbPUNQPa6N0RIwqfeOxICkcP/5JA12ypgxl3xG4ScUvvMy?=
 =?us-ascii?Q?ZLXbmGXZ9E6ttr0xTLZ59K3Hg1uX7fo7IKNFAs09CQ3OXVmeSa0/U71rb8RI?=
 =?us-ascii?Q?XEIqeQeX9nj/udZl9T/weML9NRmeMTIS5N7qL18V9LTb/Xz+cg6jYB/vrbW8?=
 =?us-ascii?Q?TLDDt4PVSJUU1dM2skZ2fSVUDxAxIjhkk8HUnBpIZhzvdxTAXfRBNIOzcu51?=
 =?us-ascii?Q?1b+M9fULp1Sq50A8pZzrT+c3sk7HzPI9gGzvYPDKTsqnu8OftkaFSB1bzIvK?=
 =?us-ascii?Q?YJjFBfopP6QeW5C4kH3xoJoX6IArf4aemMSg+qUaNH1Jd/yngZpvEV/LDXyB?=
 =?us-ascii?Q?rhPYPRS0X28DHb0F9oxhB7ThKBa1h5l7N4t2c15L3Yno81OPMhXQn5/x+s5O?=
 =?us-ascii?Q?HyEx3zvyUbz0KvV2lgYY9nRe1jydQIvVZZpd10GF?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: aCh0UgjHDkw1eoodF+Q5GMZmH3K79/rYuhMSZww3lHo2b3Ix91YkBnH+0hLAXJ1v4D+CIxcNTTZIICO4e9nvcZ+hkmJUgLwSyHrhf1uATUHMA3tSHkCNr5NJyKT0bqTmBp2jpUNmaqHcZc54Vm9IQJhCraktNv9oHOFO8xa8xSgf6TdgxOrsLkEjLgTs6wDuN6DpImW/TfIkvK7XnyKaY14cM2aj2TzmsdzlYEOW2t7YlsE/yBl83/3Td2Z/F4yIpuwqMQ76tQlW8c/92jYSFs6/q+C9GSZKCwHpYUmRyfxQIOIIdI1C8058EydK/YZkC2C0vZOSfIHqTJ+Hv67olj9r4dUYm31gwoR0r+zunm2xB/KlNKXJwKhLWFj2S3bxg3kS2TSuBs6DTI4xCykzdjqjfbNZNf5y8hm+IP6jDelVbbhvmCRslRDgCZKkxN+goNEcQHSAKyyKI7cQE+4z5xOPlePPRbYYmhPdJqIVHBy6dLO+XFLBKKMKTTIXnXGWPRX/ghbZdVUnx0GyC54K/iE5FDGJyfJEa9WXyAlwOF+EqK76uE3a+JfcEBaFoEQpFJdntmfhb+RVwMh5hd9AvYbOJ42evjTGZdedaHZw3VM=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 800219b6-fba5-47d2-f819-08dc2ddb432c
X-MS-Exchange-CrossTenant-AuthSource: DS0PR10MB7933.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 15 Feb 2024 04:04:52.9241
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: skO/ZvETsKv2WqmI4QSeg5xxW3ssM2Zyx3oYI3xOHW//mGziaWvxRh+mvAC7JyK56HtVHu09Dz0JXkdEGWmx9A==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: BLAPR10MB5300
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.1011,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2024-02-15_04,2024-02-14_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 malwarescore=0 mlxscore=0 spamscore=0
 adultscore=0 phishscore=0 bulkscore=0 mlxlogscore=729 suspectscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2311290000
 definitions=main-2402150029
X-Proofpoint-GUID: G9oKB4bg4kvAxjy2khAzR0ABob2OYZ42
X-Proofpoint-ORIG-GUID: G9oKB4bg4kvAxjy2khAzR0ABob2OYZ42
X-Original-Sender: liam.howlett@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2023-11-20 header.b=T1mUc4c7;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=DIzThlLr;       arc=pass (i=1 spf=pass spfdomain=oracle.com
 dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of liam.howlett@oracle.com designates
 205.220.177.32 as permitted sender) smtp.mailfrom=liam.howlett@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
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

* Vlastimil Babka <vbabka@suse.cz> [240214 10:14]:
> On 2/13/24 03:08, Kent Overstreet wrote:
> > On Mon, Feb 12, 2024 at 04:31:14PM -0800, Kees Cook wrote:
> >> On Mon, Feb 12, 2024 at 01:39:09PM -0800, Suren Baghdasaryan wrote:
> >> > From: Kent Overstreet <kent.overstreet@linux.dev>
> >> > 
> >> > It seems we need to be more forceful with the compiler on this one.
> >> 
> >> Sure, but why?
> > 
> > Wasn't getting inlined without it, and that's one we do want inlined -
> > it's only called in one place.
> 
> It would be better to mention this in the changelog so it's clear this is
> for performance and not e.g. needed for the code tagging to work as expected.

Since it's not needed specifically for this set, can we take this patch
out of the set (and any others) and get them upstream first?

My hope is to reduce the count of 35 patches.  Less patches might get
more reviews and small things like this (should be, are?) easy enough to
get out of the way.  But also, it sounds worth doing on its own.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240215040448.ycfrrqbv6chjeysy%40revolver.
