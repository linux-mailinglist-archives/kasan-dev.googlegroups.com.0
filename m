Return-Path: <kasan-dev+bncBCXKFB5SV4NRBBXHTWIQMGQEWLYTEXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id B85FB4D1B7F
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Mar 2022 16:17:28 +0100 (CET)
Received: by mail-pj1-x103b.google.com with SMTP id lp2-20020a17090b4a8200b001bc449ecbcesf1819520pjb.8
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Mar 2022 07:17:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646752647; cv=pass;
        d=google.com; s=arc-20160816;
        b=MIv5yC5r+HkloIi2Qgq6o8/GkhfH6krW/0QcMNTtzCrS5JlxSUwmMq9sghCnEthtXY
         IG/Y4a/QCpUwubp/bv3njR7zmRYytwWiklq/o/siFSNM8wfUiIS0XaamTIFe7w9+0tjq
         PPLQtwTUn5ZAnautq/VdriPfsq/Re2hp7UYOaQXOEZwC2b8D1YLoUWDGhro3XazOZrS1
         ryPWXcmEkpylRThIlGPORt1VfRb/yTgU3nSgpk1Oxzxtz9CrPWoXexyzOQrZH3BnDpuI
         5BmmHBqfShmA98Ou7NiiEpGwnRPXggbRVnWaAblXnRF082r1SqVUz4ghcfMr/fgprwys
         QvKw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=OkEDyBVB5bf6YOBJX5W7di6SLstYr9A2hAED61yvX2g=;
        b=hxQwvRLISlh6j4BRRsqiBV3yIdAPlZWqXdJ3GMV7wqhpKuJBG9/sknlh3TVhrJA4FV
         f7WGyh5N9brfbgNiSEnUJeMaiIdEEIiqO7nsOQv9ARx7uJzVKmeLDKmQpigiJbeRUfW4
         SMIRE75yElFe8LSNNblDE7IGmpzsatlkBugEnY/vkuNicSEiSvwb4AT+x/UKpSz9QO5d
         PsK1BTRc2HOydtEkje0IBFM9eA16uPeeGqFLFB3a8tmZ9ZYmaIdhiDrvmcjp9ipW7xU/
         582BLPV+w59COZ+KCHiwfmtfjE71mY7TTbc5FLj4K8xPrtl9Np+DBtQuwf0aeKp4qgXW
         i44A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=WWymZ9cS;
       spf=pass (google.com: domain of gor@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=gor@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references
         :content-disposition:in-reply-to:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=OkEDyBVB5bf6YOBJX5W7di6SLstYr9A2hAED61yvX2g=;
        b=qxrQMjo4p1pPLizIq+9UbVLiEB8Ww9PK5abgTsFif8y5/TuDxQticNcfxyuclXH5t0
         EuGJELHTu+AY36YA/1+lD3T4eNR6RoHCH8/raowaVQXophT5L/VBtn6+M3ZazFQNoFyM
         Ma2SYtrQATGNSttPk7ixQHssm8nlbhnmmmW7BA0dPqyr/yMVqjOAAWZ3PGeKPSgZI0Yb
         V+bhjBSbdw3DKSxObD3icslVP0imvt2MZzvjxdFc4j7qrolZkrL/7KruiqTJKO1q7WLM
         XcaUv37vkPGsLBbjGCFbjDH9wi4leGPHL7oJSP3yaEoPNM3qvQMQniPPLboNfDG+TY/3
         0Wtg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:content-disposition:in-reply-to:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=OkEDyBVB5bf6YOBJX5W7di6SLstYr9A2hAED61yvX2g=;
        b=bH+kHBmNDESLF1Ey2xTHyAWiyxIASylkmPhyeLIBVAimw8D/T4oZs+v7j6W/htE72u
         HvOpP4E+HrD1DwuaIlP8jnKkVvF9bCa4FidMUytYb5Kr7SrHaRQ1M26YQBLMYxqVnAdE
         54itdaedZIhPPuF21T/hWt0PUe7cD+Md41qdq8PoMZcFNLW0PLG67Uy+aXusZ/FAc2Ou
         id7SinAP5HAC2Lrly8uRWxiz9OXQqySxKLuyMG9hrzs/Kbbi1DdiuUShQSyn9qGDIXbX
         DZgIyk/JkiYXchRD81uGKHUU6v5BfmsmHN9ehH7AQqHyua21ypZPP5VGGd6DVyScAq34
         Q0hw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532zlRDWcOhdwSF8SJx7mki1PB4/CorJO4Iym4g8vnvsl3Kjc62q
	uHZrUAgozG+yHbjl2lb6YsI=
X-Google-Smtp-Source: ABdhPJyFhBTv5kqfnsvuWHAgCwdPOxobqP0S0tugQO20s7zGGmiv0PDq/OwAtYKHEDolaPCc1khgHQ==
X-Received: by 2002:a65:6794:0:b0:36c:460e:858d with SMTP id e20-20020a656794000000b0036c460e858dmr14434348pgr.418.1646752646990;
        Tue, 08 Mar 2022 07:17:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:8f12:0:b0:4f6:db3a:5042 with SMTP id n18-20020a628f12000000b004f6db3a5042ls4302606pfd.2.gmail;
 Tue, 08 Mar 2022 07:17:26 -0800 (PST)
X-Received: by 2002:a63:4186:0:b0:378:b438:c7ac with SMTP id o128-20020a634186000000b00378b438c7acmr14148397pga.291.1646752646276;
        Tue, 08 Mar 2022 07:17:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646752646; cv=none;
        d=google.com; s=arc-20160816;
        b=FyxRLCmxKk8szPMEMowQyw0cZIlyWYty9iFOPxZWq2gecdw/GUQPI6MX2/01s2b+Et
         htUzhyvXTuCzfc1xJnsI7oS5Y0O0q+hI4CZbzqRYZb1r8GTRBs1ApoZz0OuOQoNEpPoP
         aHHubZ7UksMcQPfWnghB6CvpDcjo3iJ5d4DZ2TIE0uAWU3lwc48BTsv31SiyWieKXagn
         03rvN1nY2k3CxsIRI8ZwrRkXIe3gC44bgmsHh6M7eT35fYJ+Y8E438K6nkh5c8DlTuMt
         fvVYvUg4AF5T4cCBwIgJwUYvem/FpLeQ1i1FlWh0HfrTHSPTmUJ5n/l3lpuI2jCOhuJF
         qSyw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=LjyKfmfP7Vu839xRleqUuDgBE/97p6EYx1iD9+26bz4=;
        b=mQk1TZjFaCtnMAM/p9u3Tce3X3mbWcK8iLkIsfHh6vmxjEkcIthuJa9GAqLsTenITn
         cCzwLS67W9BVu7uT3KBJilxwe1AWThnqVpS5WNt31M1lgLAG0/C2XUhVX0gfxwj9z7rt
         yafxuI4l0RuV740Wf06XZKrd+zt2KnMq5j2s5Gl56iwG+7J7y0rJDxCLK3LKx8eD0bS7
         3w2JqIneswgknZps6uAa6RgFljHwAgny7Ox9nI5XLtHjImKpwLSeLB3HN+BiEpbtAP8x
         7mgzMOC2yzP4YNF2DblqtHDYUR2BmmmtO6hZnx/g/GoSHdbqf1PJtU1T0R9b6wPEnO7B
         vpTg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=WWymZ9cS;
       spf=pass (google.com: domain of gor@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=gor@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id q3-20020a17090a2e0300b001b9932741a2si225413pjd.0.2022.03.08.07.17.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 08 Mar 2022 07:17:26 -0800 (PST)
Received-SPF: pass (google.com: domain of gor@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0098393.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.16.1.2/8.16.1.2) with SMTP id 228DhBWu012080;
	Tue, 8 Mar 2022 15:17:22 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com with ESMTP id 3ep03vmc0c-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 08 Mar 2022 15:17:22 +0000
Received: from m0098393.ppops.net (m0098393.ppops.net [127.0.0.1])
	by pps.reinject (8.16.0.43/8.16.0.43) with SMTP id 228EMiv6023011;
	Tue, 8 Mar 2022 15:17:21 GMT
Received: from ppma05fra.de.ibm.com (6c.4a.5195.ip4.static.sl-reverse.com [149.81.74.108])
	by mx0a-001b2d01.pphosted.com with ESMTP id 3ep03vmby9-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 08 Mar 2022 15:17:21 +0000
Received: from pps.filterd (ppma05fra.de.ibm.com [127.0.0.1])
	by ppma05fra.de.ibm.com (8.16.1.2/8.16.1.2) with SMTP id 228F7aQ1010428;
	Tue, 8 Mar 2022 15:17:19 GMT
Received: from b06cxnps3075.portsmouth.uk.ibm.com (d06relay10.portsmouth.uk.ibm.com [9.149.109.195])
	by ppma05fra.de.ibm.com with ESMTP id 3ekyg96s3t-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 08 Mar 2022 15:17:18 +0000
Received: from d06av24.portsmouth.uk.ibm.com (mk.ibm.com [9.149.105.60])
	by b06cxnps3075.portsmouth.uk.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 228FHF6Z49611084
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 8 Mar 2022 15:17:15 GMT
Received: from d06av24.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id B139842041;
	Tue,  8 Mar 2022 15:17:15 +0000 (GMT)
Received: from d06av24.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 014B04203F;
	Tue,  8 Mar 2022 15:17:15 +0000 (GMT)
Received: from localhost (unknown [9.171.12.198])
	by d06av24.portsmouth.uk.ibm.com (Postfix) with ESMTPS;
	Tue,  8 Mar 2022 15:17:14 +0000 (GMT)
Date: Tue, 8 Mar 2022 16:17:13 +0100
From: Vasily Gorbik <gor@linux.ibm.com>
To: andrey.konovalov@linux.dev
Cc: Andrew Morton <akpm@linux-foundation.org>,
        Andrey Konovalov <andreyknvl@gmail.com>,
        Marco Elver <elver@google.com>,
        Alexander Potapenko <glider@google.com>,
        Dmitry Vyukov <dvyukov@google.com>,
        Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com,
        linux-mm@kvack.org, Vincenzo Frascino <vincenzo.frascino@arm.com>,
        Catalin Marinas <catalin.marinas@arm.com>,
        Will Deacon <will@kernel.org>, Mark Rutland <mark.rutland@arm.com>,
        linux-arm-kernel@lists.infradead.org,
        Peter Collingbourne <pcc@google.com>,
        Evgenii Stepanov <eugenis@google.com>, linux-kernel@vger.kernel.org,
        Andrey Konovalov <andreyknvl@google.com>,
        Ilya Leoshkevich <iii@linux.ibm.com>
Subject: Re: [PATCH v6 31/39] kasan, vmalloc: only tag normal vmalloc
 allocations
Message-ID: <your-ad-here.call-01646752633-ext-6250@work.hours>
References: <cover.1643047180.git.andreyknvl@google.com>
 <fbfd9939a4dc375923c9a5c6b9e7ab05c26b8c6b.1643047180.git.andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <fbfd9939a4dc375923c9a5c6b9e7ab05c26b8c6b.1643047180.git.andreyknvl@google.com>
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: iDBgHtSy0Ow09BuHd6Oj4wKSrRssGLUg
X-Proofpoint-ORIG-GUID: WqPy8d8WPu5_9RZv83SYr5ei94IiJE9c
X-Proofpoint-UnRewURL: 0 URL was un-rewritten
MIME-Version: 1.0
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.205,Aquarius:18.0.816,Hydra:6.0.425,FMLib:17.11.64.514
 definitions=2022-03-08_05,2022-03-04_01,2022-02-23_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 mlxlogscore=999 mlxscore=0
 spamscore=0 clxscore=1011 malwarescore=0 bulkscore=0 priorityscore=1501
 lowpriorityscore=0 adultscore=0 phishscore=0 impostorscore=0
 suspectscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2202240000 definitions=main-2203080081
X-Original-Sender: gor@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=WWymZ9cS;       spf=pass (google.com:
 domain of gor@linux.ibm.com designates 148.163.156.1 as permitted sender)
 smtp.mailfrom=gor@linux.ibm.com;       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
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

On Mon, Jan 24, 2022 at 07:05:05PM +0100, andrey.konovalov@linux.dev wrote:
> From: Andrey Konovalov <andreyknvl@google.com>
> 
> The kernel can use to allocate executable memory. The only supported way
> to do that is via __vmalloc_node_range() with the executable bit set in
> the prot argument. (vmap() resets the bit via pgprot_nx()).
> 
> Once tag-based KASAN modes start tagging vmalloc allocations, executing
> code from such allocations will lead to the PC register getting a tag,
> which is not tolerated by the kernel.
> 
> Only tag the allocations for normal kernel pages.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

This breaks s390 and produce huge amount of false positives.
I haven't been testing linux-next with KASAN for while, now tried it with
next-20220308 and bisected false positives to this commit.

Any idea what is going wrong here?

I see 2 patterns:

[    1.123723] BUG: KASAN: vmalloc-out-of-bounds in ftrace_plt_init+0xb8/0xe0
[    1.123740] Write of size 8 at addr 001bffff80000000 by task swapper/0/1
[    1.123745]
[    1.123749] CPU: 0 PID: 1 Comm: swapper/0 Not tainted 5.17.0-rc7-118520-ga20d77ce812a #142
[    1.123755] Hardware name: IBM 8561 T01 701 (KVM/Linux)
[    1.123758] Call Trace:
[    1.123761]  [<000000000218e5fe>] dump_stack_lvl+0xc6/0xf8
[    1.123782]  [<0000000002176cb4>] print_address_description.constprop.0+0x64/0x2f0
[    1.123793]  [<000000000086fd3e>] kasan_report+0x15e/0x1c8
[    1.123802]  [<0000000000870f5c>] kasan_check_range+0x174/0x1c0
[    1.123808]  [<0000000000871988>] memcpy+0x58/0x88
[    1.123813]  [<000000000342cea8>] ftrace_plt_init+0xb8/0xe0
[    1.123819]  [<0000000000101522>] do_one_initcall+0xc2/0x468
[    1.123825]  [<000000000341ffc6>] do_initcalls+0x1be/0x1e8
[    1.123830]  [<0000000003420504>] kernel_init_freeable+0x494/0x4e8
[    1.123834]  [<0000000002196556>] kernel_init+0x2e/0x180
[    1.123838]  [<000000000010625a>] __ret_from_fork+0x8a/0xe8
[    1.123843]  [<00000000021b557a>] ret_from_fork+0xa/0x40
[    1.123852]
[    1.123854]
[    1.123856] Memory state around the buggy address:
[    1.123861]  001bffff7fffff00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
[    1.123865]  001bffff7fffff80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
[    1.123868] >001bffff80000000: f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8
[    1.123872]                    ^
[    1.123874]  001bffff80000080: f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8
[    1.123878]  001bffff80000100: f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8

$ cat /sys/kernel/debug/kernel_page_tables
---[ Modules Area Start ]---
0x001bffff80000000-0x001bffff80001000         4K PTE RO X
0x001bffff80001000-0x001bffff80002000         4K PTE I
0x001bffff80002000-0x001bffff80003000         4K PTE RO X
0x001bffff80003000-0x001bffff80004000         4K PTE I

[    1.409146] BUG: KASAN: vmalloc-out-of-bounds in bpf_jit_binary_alloc+0x138/0x170
[    1.409154] Write of size 4 at addr 001bffff80002000 by task systemd/1
[    1.409158]
[    1.409160] CPU: 0 PID: 1 Comm: systemd Tainted: G    B   W         5.17.0-rc7-118520-ga20d77ce812a #141
[    1.409166] Hardware name: IBM 8561 T01 701 (KVM/Linux)
[    1.409169] Call Trace:
[    1.409171]  [<000000000218e5fe>] dump_stack_lvl+0xc6/0xf8
[    1.409176]  [<0000000002176cb4>] print_address_description.constprop.0+0x64/0x2f0
[    1.409183]  [<000000000086fd3e>] kasan_report+0x15e/0x1c8
[    1.409188]  [<0000000000588860>] bpf_jit_binary_alloc+0x138/0x170
[    1.409192]  [<000000000019fa84>] bpf_int_jit_compile+0x814/0xca8
[    1.409197]  [<000000000058b60e>] bpf_prog_select_runtime+0x286/0x3e8
[    1.409202]  [<000000000059ac2e>] bpf_prog_load+0xe66/0x1a10
[    1.409206]  [<000000000059ebd4>] __sys_bpf+0x8bc/0x1088
[    1.409211]  [<000000000059f9e8>] __s390x_sys_bpf+0x98/0xc8
[    1.409216]  [<000000000010ce74>] do_syscall+0x22c/0x328
[    1.409221]  [<000000000219599c>] __do_syscall+0x94/0xf0
[    1.409226]  [<00000000021b5542>] system_call+0x82/0xb0
[    1.409232]
[    1.409234]
[    1.409235] Memory state around the buggy address:
[    1.409238]  001bffff80001f00: f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8
[    1.409242]  001bffff80001f80: f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8
[    1.409246] >001bffff80002000: f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8
[    1.409249]                    ^
[    1.409251]  001bffff80002080: f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8
[    1.409255]  001bffff80002100: f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8

$ git bisect log
git bisect start
# good: [ea4424be16887a37735d6550cfd0611528dbe5d9] Merge tag 'mtd/fixes-for-5.17-rc8' of git://git.kernel.org/pub/scm/linux/kernel/git/mtd/linux
git bisect good ea4424be16887a37735d6550cfd0611528dbe5d9
# bad: [cb153b68ff91cbc434f3de70ac549e110543e1bb] Add linux-next specific files for 20220308
git bisect bad cb153b68ff91cbc434f3de70ac549e110543e1bb
# good: [1ce7aac49a7b73abbd691c6e6a1577a449d90bad] Merge branch 'master' of git://git.kernel.org/pub/scm/linux/kernel/git/herbert/cryptodev-2.6.git
git bisect good 1ce7aac49a7b73abbd691c6e6a1577a449d90bad
# good: [08688e100b1b07ce178c1d3c6b9983e00cd85413] Merge branch 'for-next' of git://git.kernel.org/pub/scm/linux/kernel/git/rostedt/linux-trace.git
git bisect good 08688e100b1b07ce178c1d3c6b9983e00cd85413
# good: [82a204646439657e5c2f94da5cad7ba96de10414] Merge branch 'togreg' of git://git.kernel.org/pub/scm/linux/kernel/git/jic23/iio.git
git bisect good 82a204646439657e5c2f94da5cad7ba96de10414
# good: [ac82bf337c937458bf4f75985857bf3a68cd7c16] Merge branch 'next' of git://git.kernel.org/pub/scm/linux/kernel/git/cxl/cxl.git
git bisect good ac82bf337c937458bf4f75985857bf3a68cd7c16
# good: [a36f330518af9bd205451bedb4eb22a5245cf010] ipc/mqueue: use get_tree_nodev() in mqueue_get_tree()
git bisect good a36f330518af9bd205451bedb4eb22a5245cf010
# good: [339c1d0fb400ab3acd2da2d9990242f654689f6e] Merge branch 'for-next' of git://git.infradead.org/users/willy/pagecache.git
git bisect good 339c1d0fb400ab3acd2da2d9990242f654689f6e
# good: [b8a58fecbd4982211f528d405a9ded00ddc7d646] kasan: only apply __GFP_ZEROTAGS when memory is zeroed
git bisect good b8a58fecbd4982211f528d405a9ded00ddc7d646
# bad: [141e05389762bee5fb0eb54af9c4d5266ce11d26] kasan: drop addr check from describe_object_addr
git bisect bad 141e05389762bee5fb0eb54af9c4d5266ce11d26
# good: [97fedbc9a6bccd508c392b0e177380313dd9fcd2] kasan, page_alloc: allow skipping unpoisoning for HW_TAGS
git bisect good 97fedbc9a6bccd508c392b0e177380313dd9fcd2
# bad: [606c2ee3fabbf66594f39998be9b5a21c2bf5dff] arm64: select KASAN_VMALLOC for SW/HW_TAGS modes
git bisect bad 606c2ee3fabbf66594f39998be9b5a21c2bf5dff
# bad: [bd2c296805cff9572080bf56807c16d1dd382260] kasan, scs: support tagged vmalloc mappings
git bisect bad bd2c296805cff9572080bf56807c16d1dd382260
# good: [7b80fa947b3a3ee746115395d1c5f7157119b7d2] kasan, vmalloc: add vmalloc tagging for HW_TAGS
git bisect good 7b80fa947b3a3ee746115395d1c5f7157119b7d2
# bad: [f51c09448ea124622f8ebcfb41d06c809ee01bca] fix for "kasan, vmalloc: only tag normal vmalloc allocations"
git bisect bad f51c09448ea124622f8ebcfb41d06c809ee01bca
# bad: [a20d77ce812a3e11b3cf2cb4f411904bb5c6edaa] kasan, vmalloc: only tag normal vmalloc allocations
git bisect bad a20d77ce812a3e11b3cf2cb4f411904bb5c6edaa
# first bad commit: [a20d77ce812a3e11b3cf2cb4f411904bb5c6edaa] kasan, vmalloc: only tag normal vmalloc allocations

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/your-ad-here.call-01646752633-ext-6250%40work.hours.
