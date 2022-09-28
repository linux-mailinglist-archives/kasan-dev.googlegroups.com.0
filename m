Return-Path: <kasan-dev+bncBC4LXIPCY4NRBJHG3GMQMGQEJ7WBZ3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 8A5115F039E
	for <lists+kasan-dev@lfdr.de>; Fri, 30 Sep 2022 06:40:05 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id t24-20020a19dc18000000b004a20fbbbcfcsf602006lfg.6
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Sep 2022 21:40:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1664512805; cv=pass;
        d=google.com; s=arc-20160816;
        b=BLTsDpu1V5ihOeQXILAC+h1xkbjGXEmZWEylUC4iRxPgbog7DkZYpsqvbLPxIx/mLF
         8Be1WAGDAxwK+NUtHm2W7Bt3qEYtI4qTb0Zz1/PCEIqq121C5wUq5Bhukax4NgLlP9pi
         NWC5Z6itg2keS9SHqHGWTYlh4sqeJjhVMzlvudC/47U9plQG3NV7nUTxw1AuaTn+VUix
         pVzSlP1JWC/eWAF0po1+1nOcDgBDnWifmbOsW04rTBsYPeXhABJQFLDlKLQo6jFjopVo
         szX6UBHDzVy+a8Ryi06Hxe1xWjCs3Vzp1A9uyV2xnCp1BFbYF8Yyw87tunShVnMXH09k
         gnzA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=ZxQ4MiVEYgh0SKlstcZ5O1XcdypV6UgOhF3WzhS7qVg=;
        b=M+ZE/N3P3ZJIEJryhwJmg3KXchrfXZaqSxiiyEN2PCarbbxmQieC4+FVC3xzrtG4lh
         nEfM/2Evf7MNEY/52MBbh1G5q/48QP4UGRHX48bhgSHy2X3VYbw575RVF3gtQaks+K9o
         tPvp9PhNM+sRRF4kjkWKq95ekmH4SvZag13TeBHCrPySCA9OqB7ov6UJHAB8A/IrdlIa
         z5vgbPThRUe+d1i9vqbTk8PPX62QE7Jj0TYUnjVTHF4Mwke3m4uejxBdDXCU3HhEmX/Z
         HYMoz3+QJONituNYQDxr2qADZSG6lxv8+/NkRjyGfQ9UrLjq/0MHGUXXLPF5fROYl/d5
         AAEg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=LnqwsK9j;
       spf=pass (google.com: domain of lkp@intel.com designates 192.55.52.151 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=ZxQ4MiVEYgh0SKlstcZ5O1XcdypV6UgOhF3WzhS7qVg=;
        b=KeUwh6FBkd/zdstqBmZ11WBZcVXw1y5kDbDoGysfHmbKRcyT5exZlC1oP9UWReM1cp
         VJqmuAjEpV5ERALk7bGHoKs3X6auL37cv1XyrxKU4vCjkNrgzyIBNzAWbdxDig9sf42X
         /A3TGJBuCYMtIeqTBTepJBCP9AJlsAzb3rHWZ+OxdxM5m+KIjot3soqokEKhQ2WrZ+/G
         VZ3AV42X1LxxQC/ZJ5aFIejSXMDX6gyyj5gx96wQlalxNz8OaQbWOIBqWHY/7oK6zi/g
         YXr34T178WneCuvet30gsS2NR0wVuLvJHE0+n88ZNdM2QRO5gFOn5ZMnpwara3ejlzi6
         JKBQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=ZxQ4MiVEYgh0SKlstcZ5O1XcdypV6UgOhF3WzhS7qVg=;
        b=Lj8ELRNxomz1lWAx1kVrBIT5XzYwzr6zFbC6bD6bYo8rgEKKT6EnyTyX5fbKGnCMxn
         /rR4jrsefhvPwYNJLEbJH3By17xByNaeH+5/BUtnmdlF5qcdQ9+kjuJ+/9Y72FMO97kF
         tY3HqSBnpp0zIT0/iJRSlUdg8NpSVIebxWhSxIlBviYUJPGnnbbB1SZDsLwe0Gi1LxmF
         AYmSS5369xuuSKYHwC8iqGJuUIBHyHxWmF8+vCDVuBWPjUq5RwBnp94OysvjhcAJSz/a
         /YjYETE41JFMVRi4fY4p7qkvlN01R3sJFCT+9qiru0GhACWr884YNZOTyPoGk8IbBmik
         pEDg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf00WnAlVaSdplPg/NLtOect+0i/c60IwAW3lSxLQCc27GGx9w1c
	LTrtXiLUo4DYoTeAaMByyrM=
X-Google-Smtp-Source: AMsMyM62/OgB4b5QhhOIcjU0eNxXRFKI3uphq9sRBVMns8NJTOwir8JyPryk2WpY5eiK/1YP/UuEpA==
X-Received: by 2002:a2e:a30f:0:b0:26d:9162:9451 with SMTP id l15-20020a2ea30f000000b0026d91629451mr2411664lje.164.1664512804342;
        Thu, 29 Sep 2022 21:40:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:884d:0:b0:26c:50e7:2c36 with SMTP id z13-20020a2e884d000000b0026c50e72c36ls643155ljj.2.-pod-prod-gmail;
 Thu, 29 Sep 2022 21:40:03 -0700 (PDT)
X-Received: by 2002:a2e:bf13:0:b0:26d:8e26:f4b8 with SMTP id c19-20020a2ebf13000000b0026d8e26f4b8mr2482143ljr.117.1664512802551;
        Thu, 29 Sep 2022 21:40:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1664512802; cv=none;
        d=google.com; s=arc-20160816;
        b=vP0GXif/UGbmZhBFuI1LCNCjU54bfx9cf7fMTJllvNnfZcNJgtEn2dzoGWQhE/fHsQ
         ZpcsL4AzI9Byp7TENUBXS91j7vfhSnsx2Oec1j+ANqkXYmjS2l0zFjm9m4gtxGzh5uyA
         tcHE9UU9inVXPL3fN1Te5LgD3WshG7dbouEM1cbY4L9XFCk3jhlySEQond7o1kqov2DE
         YtzByvYkAkqYpZgExqKMJceF7ahsSflo3ZLR/M+4Uq8I8GknPzE+wUKIuBTzEQkKeFG9
         E5LpyY9APIx82qDAINosVQnsGOY7gM7yKZcFuBHJVhjq0NWLP+vjta5gE44uABuIwKyu
         0wyw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=RFyzuNRupW/eL76BEB6guhsRWZMEVoInlRX65R4Vf48=;
        b=LcuqGcBKQrSroi+Xd8k29KkvxhCRXJ7QqcH2fHNblKzA3KYdcXeSn2UHZro5cdaEax
         mRtoZWuNxYt0GBeGEO2yIl8njJBYRUbaNzGw6OA6JfWLc1Lk9LDhgtZOwBVepYanH6rv
         jnt6Ajh5cYFcnKIwVBaiZlylbd8th2vB+G0Z1yTssMUMrYvsMEGGcLFMkj0fFgx1jTZc
         bjVafFDWEsdE3VtXtO9cv7zXB/Q8ky5CG/e+MhoyC50WhS4q0PYhBszio/iImgfg5hRx
         sW2g9wkcSC7+msXs8A9MM0L9wj5uM6rgJNSxDhwwLPFre8siLHBOZi/rH4j487tsPFyv
         B32g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=LnqwsK9j;
       spf=pass (google.com: domain of lkp@intel.com designates 192.55.52.151 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga17.intel.com (mga17.intel.com. [192.55.52.151])
        by gmr-mx.google.com with ESMTPS id f15-20020a056512360f00b0049ba11e2f38si35431lfs.11.2022.09.29.21.40.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 29 Sep 2022 21:40:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 192.55.52.151 as permitted sender) client-ip=192.55.52.151;
X-IronPort-AV: E=McAfee;i="6500,9779,10485"; a="282464564"
X-IronPort-AV: E=Sophos;i="5.93,357,1654585200"; 
   d="scan'208";a="282464564"
Received: from fmsmga008.fm.intel.com ([10.253.24.58])
  by fmsmga107.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 29 Sep 2022 21:39:57 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6500,9779,10485"; a="685137806"
X-IronPort-AV: E=Sophos;i="5.93,357,1654585200"; 
   d="scan'208";a="685137806"
Received: from lkp-server01.sh.intel.com (HELO 14cc182da2d0) ([10.239.97.150])
  by fmsmga008.fm.intel.com with ESMTP; 29 Sep 2022 21:39:53 -0700
Received: from kbuild by 14cc182da2d0 with local (Exim 4.96)
	(envelope-from <lkp@intel.com>)
	id 1oe7oW-0000KQ-1q;
	Fri, 30 Sep 2022 04:39:52 +0000
Date: Thu, 29 Sep 2022 02:10:52 +0800
From: kernel test robot <lkp@intel.com>
To: Peter Collingbourne <pcc@google.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andrey Konovalov <andreyknvl@gmail.com>
Cc: kbuild-all@lists.01.org,
	Linux Memory Management List <linux-mm@kvack.org>,
	Peter Collingbourne <pcc@google.com>,
	linux-arm-kernel@lists.infradead.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH v2] kasan: also display registers for reports from HW
 exceptions
Message-ID: <202209290103.pnpDQUWv-lkp@intel.com>
References: <20220927012044.2794384-1-pcc@google.com>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="0Z4F7SWuvvF4NXmZ"
Content-Disposition: inline
In-Reply-To: <20220927012044.2794384-1-pcc@google.com>
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=LnqwsK9j;       spf=pass
 (google.com: domain of lkp@intel.com designates 192.55.52.151 as permitted
 sender) smtp.mailfrom=lkp@intel.com;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=intel.com
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


--0Z4F7SWuvvF4NXmZ
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline

Hi Peter,

Thank you for the patch! Perhaps something to improve:

[auto build test WARNING on akpm-mm/mm-everything]
[also build test WARNING on next-20220927]
[cannot apply to arm64/for-next/core linus/master v6.0-rc7]
[If your patch is applied to the wrong git tree, kindly drop us a note.
And when submitting patch, we suggest to use '--base' as documented in
https://git-scm.com/docs/git-format-patch#_base_tree_information]

url:    https://github.com/intel-lab-lkp/linux/commits/Peter-Collingbourne/kasan-also-display-registers-for-reports-from-HW-exceptions/20220927-092847
base:   https://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm.git mm-everything
config: x86_64-allyesconfig
compiler: gcc-11 (Debian 11.3.0-5) 11.3.0
reproduce (this is a W=1 build):
        # https://github.com/intel-lab-lkp/linux/commit/010a23f5998ecdcc86e8dd37393862861dbd7e55
        git remote add linux-review https://github.com/intel-lab-lkp/linux
        git fetch --no-tags linux-review Peter-Collingbourne/kasan-also-display-registers-for-reports-from-HW-exceptions/20220927-092847
        git checkout 010a23f5998ecdcc86e8dd37393862861dbd7e55
        # save the config file
        mkdir build_dir && cp config build_dir/.config
        make W=1 O=build_dir ARCH=x86_64 SHELL=/bin/bash

If you fix the issue, kindly add following tag where applicable
| Reported-by: kernel test robot <lkp@intel.com>

All warnings (new ones prefixed by >>):

>> vmlinux.o: warning: objtool: .altinstr_replacement+0x2c37: redundant UACCESS disable
   vmlinux.o: warning: objtool: kasan_report+0xa: call to __kasan_report() with UACCESS enabled
   vmlinux.o: warning: objtool: check_stackleak_irqoff+0x309: call to _printk() leaves .noinstr.text section


objdump-func vmlinux.o .altinstr_replacement:
0000 0000000000000000 <.altinstr_replacement>:
0000        0:	0f 22 df             	mov    %rdi,%cr3
0003        3:	0f 20 d8             	mov    %cr3,%rax
0006        6:	e8 00 00 00 00       	call   b <.altinstr_replacement+0xb>	7: R_X86_64_PLT32	clear_page_rep-0x4
000b        b:	e8 00 00 00 00       	call   10 <.altinstr_replacement+0x10>	c: R_X86_64_PLT32	clear_page_erms-0x4
0010       10:	9c                   	pushf
0011       11:	58                   	pop    %rax
0012       12:	fa                   	cli
0013       13:	9c                   	pushf
0014       14:	58                   	pop    %rax
0015       15:	fb                   	sti
0016       16:	9c                   	pushf
0017       17:	58                   	pop    %rax
0018       18:	fa                   	cli
0019       19:	9c                   	pushf
001a       1a:	58                   	pop    %rax
001b       1b:	9c                   	pushf
001c       1c:	58                   	pop    %rax
001d       1d:	fa                   	cli
001e       1e:	9c                   	pushf
001f       1f:	58                   	pop    %rax
0020       20:	fb                   	sti
0021       21:	9c                   	pushf
0022       22:	58                   	pop    %rax
0023       23:	fb                   	sti
0024       24:	9c                   	pushf
0025       25:	58                   	pop    %rax
0026       26:	48 0f ba ec 3f       	bts    $0x3f,%rsp
002b       2b:	e8 00 00 00 00       	call   30 <.altinstr_replacement+0x30>	2c: R_X86_64_PLT32	zen_untrain_ret-0x4
0030       30:	e8 00 00 00 00       	call   35 <.altinstr_replacement+0x35>	31: R_X86_64_PLT32	entry_ibpb-0x4
0035       35:	e9 00 00 00 00       	jmp    3a <.altinstr_replacement+0x3a>	36: R_X86_64_PLT32	swapgs_restore_regs_and_return_to_usermode-0x4
003a       3a:	48 c1 e1 07          	shl    $0x7,%rcx
003e       3e:	48 c1 f9 07          	sar    $0x7,%rcx
0042       42:	49 c7 c4 10 00 00 00 	mov    $0x10,%r12
0049       49:	e8 01 00 00 00       	call   4f <.altinstr_replacement+0x4f>
004e       4e:	cc                   	int3
004f       4f:	e8 01 00 00 00       	call   55 <.altinstr_replacement+0x55>
0054       54:	cc                   	int3
0055       55:	48 83 c4 10          	add    $0x10,%rsp
0059       59:	49 ff cc             	dec    %r12
005c       5c:	75 eb                	jne    49 <.altinstr_replacement+0x49>
005e       5e:	0f ae e8             	lfence
0061       61:	e8 01 00 00 00       	call   67 <.altinstr_replacement+0x67>
0066       66:	cc                   	int3
0067       67:	48 83 c4 08          	add    $0x8,%rsp
006b       6b:	0f ae e8             	lfence
006e       6e:	e8 00 00 00 00       	call   73 <.altinstr_replacement+0x73>	6f: R_X86_64_PLT32	zen_untrain_ret-0x4
0073       73:	e8 00 00 00 00       	call   78 <.altinstr_replacement+0x78>	74: R_X86_64_PLT32	entry_ibpb-0x4
0078       78:	0f 01 ca             	clac
007b       7b:	e8 00 00 00 00       	call   80 <.altinstr_replacement+0x80>	7c: R_X86_64_PC32	.entry.text+0x1fc
0080       80:	0f 01 ca             	clac
0083       83:	e8 00 00 00 00       	call   88 <.altinstr_replacement+0x88>	84: R_X86_64_PC32	.entry.text+0x1fc
0088       88:	0f 01 ca             	clac
008b       8b:	e8 00 00 00 00       	call   90 <.altinstr_replacement+0x90>	8c: R_X86_64_PC32	.entry.text+0x1fc
0090       90:	0f 01 ca             	clac
0093       93:	e8 00 00 00 00       	call   98 <.altinstr_replacement+0x98>	94: R_X86_64_PC32	.entry.text+0x1fc
0098       98:	0f 01 ca             	clac
009b       9b:	e8 00 00 00 00       	call   a0 <.altinstr_replacement+0xa0>	9c: R_X86_64_PC32	.entry.text+0x1fc
00a0       a0:	0f 01 ca             	clac
00a3       a3:	e8 00 00 00 00       	call   a8 <.altinstr_replacement+0xa8>	a4: R_X86_64_PC32	.entry.text+0x1fc
00a8       a8:	0f 01 ca             	clac
00ab       ab:	e8 00 00 00 00       	call   b0 <.altinstr_replacement+0xb0>	ac: R_X86_64_PC32	.entry.text+0x1fc
00b0       b0:	0f 01 ca             	clac
00b3       b3:	e8 00 00 00 00       	call   b8 <.altinstr_replacement+0xb8>	b4: R_X86_64_PC32	.entry.text+0x1fc
00b8       b8:	0f 01 ca             	clac
00bb       bb:	e8 00 00 00 00       	call   c0 <.altinstr_replacement+0xc0>	bc: R_X86_64_PC32	.entry.text+0x1fc
00c0       c0:	0f 01 ca             	clac
00c3       c3:	e8 00 00 00 00       	call   c8 <.altinstr_replacement+0xc8>	c4: R_X86_64_PC32	.entry.text+0x1fc
00c8       c8:	0f 01 ca             	clac
00cb       cb:	e8 00 00 00 00       	call   d0 <.altinstr_replacement+0xd0>	cc: R_X86_64_PC32	.entry.text+0x1fc
00d0       d0:	0f 01 ca             	clac
00d3       d3:	e8 00 00 00 00       	call   d8 <.altinstr_replacement+0xd8>	d4: R_X86_64_PC32	.entry.text+0x1fc
00d8       d8:	0f 01 ca             	clac
00db       db:	e8 00 00 00 00       	call   e0 <.altinstr_replacement+0xe0>	dc: R_X86_64_PC32	.entry.text+0x1fc
00e0       e0:	0f 01 ca             	clac
00e3       e3:	e8 00 00 00 00       	call   e8 <.altinstr_replacement+0xe8>	e4: R_X86_64_PC32	.entry.text+0x1fc
00e8       e8:	0f 01 ca             	clac
00eb       eb:	e8 00 00 00 00       	call   f0 <.altinstr_replacement+0xf0>	ec: R_X86_64_PC32	.entry.text+0x1fc
00f0       f0:	0f 01 ca             	clac
00f3       f3:	e8 00 00 00 00       	call   f8 <.altinstr_replacement+0xf8>	f4: R_X86_64_PC32	.entry.text+0x1fc
00f8       f8:	0f 01 ca             	clac
00fb       fb:	e8 00 00 00 00       	call   100 <.altinstr_replacement+0x100>	fc: R_X86_64_PC32	.entry.text+0x1fc
0100      100:	0f 01 ca             	clac
0103      103:	e8 00 00 00 00       	call   108 <.altinstr_replacement+0x108>	104: R_X86_64_PC32	.entry.text+0x1fc
0108      108:	0f 01 ca             	clac
010b      10b:	e8 00 00 00 00       	call   110 <.altinstr_replacement+0x110>	10c: R_X86_64_PC32	.entry.text+0x1fc
0110      110:	0f 01 ca             	clac
0113      113:	e8 00 00 00 00       	call   118 <.altinstr_replacement+0x118>	114: R_X86_64_PC32	.entry.text+0x1fc
0118      118:	0f 01 ca             	clac
011b      11b:	e8 00 00 00 00       	call   120 <.altinstr_replacement+0x120>	11c: R_X86_64_PC32	.entry.text+0x1fc
0120      120:	0f 01 ca             	clac
0123      123:	e8 00 00 00 00       	call   128 <.altinstr_replacement+0x128>	124: R_X86_64_PC32	.entry.text+0x1fc
0128      128:	0f 01 ca             	clac
012b      12b:	0f 01 ca             	clac
012e      12e:	e8 00 00 00 00       	call   133 <.altinstr_replacement+0x133>	12f: R_X86_64_PC32	.entry.text+0x1fc
0133      133:	0f 01 ca             	clac
0136      136:	e8 00 00 00 00       	call   13b <.altinstr_replacement+0x13b>	137: R_X86_64_PC32	.entry.text+0x1fc
013b      13b:	0f 01 ca             	clac
013e      13e:	e8 00 00 00 00       	call   143 <.altinstr_replacement+0x143>	13f: R_X86_64_PC32	.entry.text+0x1fc
0143      143:	0f 01 ca             	clac
0146      146:	e8 00 00 00 00       	call   14b <.altinstr_replacement+0x14b>	147: R_X86_64_PC32	.entry.text+0x1fc
014b      14b:	0f 01 ca             	clac
014e      14e:	e8 00 00 00 00       	call   153 <.altinstr_replacement+0x153>	14f: R_X86_64_PC32	.entry.text+0x1fc
0153      153:	0f 01 ca             	clac
0156      156:	e8 00 00 00 00       	call   15b <.altinstr_replacement+0x15b>	157: R_X86_64_PC32	.entry.text+0x1fc
015b      15b:	0f 01 ca             	clac
015e      15e:	e8 00 00 00 00       	call   163 <.altinstr_replacement+0x163>	15f: R_X86_64_PC32	.entry.text+0x1fc
0163      163:	0f 01 ca             	clac
0166      166:	e8 00 00 00 00       	call   16b <.altinstr_replacement+0x16b>	167: R_X86_64_PC32	.entry.text+0x1fc
016b      16b:	0f 01 ca             	clac
016e      16e:	e8 00 00 00 00       	call   173 <.altinstr_replacement+0x173>	16f: R_X86_64_PC32	.entry.text+0x1fc
0173      173:	0f 01 ca             	clac
0176      176:	e8 00 00 00 00       	call   17b <.altinstr_replacement+0x17b>	177: R_X86_64_PC32	.entry.text+0x1fc
017b      17b:	0f 01 ca             	clac
017e      17e:	e8 00 00 00 00       	call   183 <.altinstr_replacement+0x183>	17f: R_X86_64_PC32	.entry.text+0x1fc
0183      183:	0f 01 ca             	clac
0186      186:	e8 00 00 00 00       	call   18b <.altinstr_replacement+0x18b>	187: R_X86_64_PC32	.entry.text+0x1fc
018b      18b:	0f 01 ca             	clac
018e      18e:	e8 00 00 00 00       	call   193 <.altinstr_replacement+0x193>	18f: R_X86_64_PC32	.entry.text+0x1fc
0193      193:	0f 01 ca             	clac
0196      196:	e8 00 00 00 00       	call   19b <.altinstr_replacement+0x19b>	197: R_X86_64_PC32	.entry.text+0x1fc
019b      19b:	0f 01 ca             	clac
019e      19e:	e8 00 00 00 00       	call   1a3 <.altinstr_replacement+0x1a3>	19f: R_X86_64_PC32	.entry.text+0x1fc
01a3      1a3:	0f 01 ca             	clac
01a6      1a6:	e8 00 00 00 00       	call   1ab <.altinstr_replacement+0x1ab>	1a7: R_X86_64_PC32	.entry.text+0x1fc
01ab      1ab:	0f 01 ca             	clac
01ae      1ae:	e8 00 00 00 00       	call   1b3 <.altinstr_replacement+0x1b3>	1af: R_X86_64_PC32	.entry.text+0x1fc
01b3      1b3:	0f 01 ca             	clac
01b6      1b6:	e8 00 00 00 00       	call   1bb <.altinstr_replacement+0x1bb>	1b7: R_X86_64_PC32	.entry.text+0x1fc
01bb      1bb:	0f 01 ca             	clac
01be      1be:	e8 00 00 00 00       	call   1c3 <.altinstr_replacement+0x1c3>	1bf: R_X86_64_PC32	.entry.text+0x1fc
01c3      1c3:	0f 01 ca             	clac
01c6      1c6:	e8 00 00 00 00       	call   1cb <.altinstr_replacement+0x1cb>	1c7: R_X86_64_PC32	.entry.text+0x1fc
01cb      1cb:	0f 01 ca             	clac
01ce      1ce:	e8 00 00 00 00       	call   1d3 <.altinstr_replacement+0x1d3>	1cf: R_X86_64_PC32	.entry.text+0x1fc
01d3      1d3:	0f 01 ca             	clac
01d6      1d6:	e8 00 00 00 00       	call   1db <.altinstr_replacement+0x1db>	1d7: R_X86_64_PC32	.entry.text+0x1fc
01db      1db:	0f 01 ca             	clac
01de      1de:	e8 00 00 00 00       	call   1e3 <.altinstr_replacement+0x1e3>	1df: R_X86_64_PC32	.entry.text+0x1fc
01e3      1e3:	0f 01 ca             	clac
01e6      1e6:	e8 00 00 00 00       	call   1eb <.altinstr_replacement+0x1eb>	1e7: R_X86_64_PC32	.entry.text+0x1fc
01eb      1eb:	0f 01 ca             	clac
01ee      1ee:	e8 00 00 00 00       	call   1f3 <.altinstr_replacement+0x1f3>	1ef: R_X86_64_PC32	.entry.text+0x1fc
01f3      1f3:	0f 01 ca             	clac
01f6      1f6:	e8 00 00 00 00       	call   1fb <.altinstr_replacement+0x1fb>	1f7: R_X86_64_PC32	.entry.text+0x1fc
01fb      1fb:	0f 01 ca             	clac
01fe      1fe:	e8 00 00 00 00       	call   203 <.altinstr_replacement+0x203>	1ff: R_X86_64_PC32	.entry.text+0x1fc
0203      203:	0f 01 ca             	clac
0206      206:	e8 00 00 00 00       	call   20b <.altinstr_replacement+0x20b>	207: R_X86_64_PC32	.entry.text+0x1fc
020b      20b:	0f 01 ca             	clac
020e      20e:	e8 00 00 00 00       	call   213 <.altinstr_replacement+0x213>	20f: R_X86_64_PC32	.entry.text+0x1fc
0213      213:	0f 01 ca             	clac
0216      216:	e8 00 00 00 00       	call   21b <.altinstr_replacement+0x21b>	217: R_X86_64_PC32	.entry.text+0x1fc
021b      21b:	e9 00 00 00 00       	jmp    220 <.altinstr_replacement+0x220>	21c: R_X86_64_PLT32	xenpv_restore_regs_and_return_to_usermode-0x4
0220      220:	48 0f ba ef 3f       	bts    $0x3f,%rdi
0225      225:	0f ae f0             	mfence
0228      228:	b8 2b 00 00 00       	mov    $0x2b,%eax
022d      22d:	8e e8                	mov    %eax,%gs
022f      22f:	48 0f ba e8 3f       	bts    $0x3f,%rax
0234      234:	0f ae e8             	lfence
0237      237:	e8 00 00 00 00       	call   23c <.altinstr_replacement+0x23c>	238: R_X86_64_PLT32	zen_untrain_ret-0x4
023c      23c:	e8 00 00 00 00       	call   241 <.altinstr_replacement+0x241>	23d: R_X86_64_PLT32	entry_ibpb-0x4
0241      241:	0f ae e8             	lfence
0244      244:	48 0f ba e8 3f       	bts    $0x3f,%rax
0249      249:	e8 00 00 00 00       	call   24e <.altinstr_replacement+0x24e>	24a: R_X86_64_PLT32	zen_untrain_ret-0x4
024e      24e:	e8 00 00 00 00       	call   253 <.altinstr_replacement+0x253>	24f: R_X86_64_PLT32	entry_ibpb-0x4
0253      253:	0f ae e8             	lfence
0256      256:	0f ae e8             	lfence
0259      259:	48 0f ba e8 3f       	bts    $0x3f,%rax
025e      25e:	e8 00 00 00 00       	call   263 <.altinstr_replacement+0x263>	25f: R_X86_64_PLT32	zen_untrain_ret-0x4
0263      263:	e8 00 00 00 00       	call   268 <.altinstr_replacement+0x268>	264: R_X86_64_PLT32	entry_ibpb-0x4
0268      268:	9c                   	pushf
0269      269:	58                   	pop    %rax
026a      26a:	0f 01 ca             	clac
026d      26d:	0f ae e8             	lfence
0270      270:	48 0f ba ea 3f       	bts    $0x3f,%rdx
0275      275:	e8 00 00 00 00       	call   27a <.altinstr_replacement+0x27a>	276: R_X86_64_PLT32	zen_untrain_ret-0x4
027a      27a:	e8 00 00 00 00       	call   27f <.altinstr_replacement+0x27f>	27b: R_X86_64_PLT32	entry_ibpb-0x4
027f      27f:	9c                   	pushf
0280      280:	58                   	pop    %rax
0281      281:	fa                   	cli
0282      282:	48 b9 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rcx
028c      28c:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
0296      296:	48 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbp
02a0      2a0:	48 89 f8             	mov    %rdi,%rax
02a3      2a3:	48 89 f8             	mov    %rdi,%rax
02a6      2a6:	48 89 f8             	mov    %rdi,%rax
02a9      2a9:	48 89 f8             	mov    %rdi,%rax
02ac      2ac:	e9 00 00 00 00       	jmp    2b1 <.altinstr_replacement+0x2b1>	2ad: R_X86_64_PC32	.init.text+0xc313
02b1      2b1:	e9 00 00 00 00       	jmp    2b6 <.altinstr_replacement+0x2b6>	2b2: R_X86_64_PC32	.init.text+0xc3cb
02b6      2b6:	48 89 f8             	mov    %rdi,%rax
02b9      2b9:	48 89 f8             	mov    %rdi,%rax
02bc      2bc:	48 89 f8             	mov    %rdi,%rax
02bf      2bf:	48 89 f8             	mov    %rdi,%rax
02c2      2c2:	48 0f ba e8 3f       	bts    $0x3f,%rax
02c7      2c7:	e8 00 00 00 00       	call   2cc <.altinstr_replacement+0x2cc>	2c8: R_X86_64_PLT32	zen_untrain_ret-0x4
02cc      2cc:	e8 00 00 00 00       	call   2d1 <.altinstr_replacement+0x2d1>	2cd: R_X86_64_PLT32	entry_ibpb-0x4
02d1      2d1:	e9 00 00 00 00       	jmp    2d6 <.altinstr_replacement+0x2d6>	2d2: R_X86_64_PLT32	swapgs_restore_regs_and_return_to_usermode-0x4
02d6      2d6:	48 0f ba ec 3f       	bts    $0x3f,%rsp
02db      2db:	e8 00 00 00 00       	call   2e0 <.altinstr_replacement+0x2e0>	2dc: R_X86_64_PLT32	zen_untrain_ret-0x4
02e0      2e0:	e8 00 00 00 00       	call   2e5 <.altinstr_replacement+0x2e5>	2e1: R_X86_64_PLT32	entry_ibpb-0x4
02e5      2e5:	e9 00 00 00 00       	jmp    2ea <.altinstr_replacement+0x2ea>	2e6: R_X86_64_PLT32	swapgs_restore_regs_and_return_to_usermode-0x4
02ea      2ea:	0f 01 ca             	clac
02ed      2ed:	48 0f ba e8 3f       	bts    $0x3f,%rax
02f2      2f2:	e9 00 00 00 00       	jmp    2f7 <.altinstr_replacement+0x2f7>	2f3: R_X86_64_PC32	.entry.text+0x220e
02f7      2f7:	e8 00 00 00 00       	call   2fc <.altinstr_replacement+0x2fc>	2f8: R_X86_64_PLT32	zen_untrain_ret-0x4
02fc      2fc:	e8 00 00 00 00       	call   301 <.altinstr_replacement+0x301>	2fd: R_X86_64_PLT32	entry_ibpb-0x4
0301      301:	f3 48 0f b8 c7       	popcnt %rdi,%rax
0306      306:	9c                   	pushf
0307      307:	58                   	pop    %rax
0308      308:	fa                   	cli
0309      309:	9c                   	pushf
030a      30a:	58                   	pop    %rax
030b      30b:	fb                   	sti
030c      30c:	f3 48 0f b8 c7       	popcnt %rdi,%rax
0311      311:	48 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbp
031b      31b:	48 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbp
0325      325:	48 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbp
032f      32f:	49 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r13
0339      339:	f3 0f b8 c7          	popcnt %edi,%eax
033d      33d:	f3 48 0f b8 c7       	popcnt %rdi,%rax
0342      342:	f3 48 0f b8 c7       	popcnt %rdi,%rax
0347      347:	e9 00 00 00 00       	jmp    34c <.altinstr_replacement+0x34c>	348: R_X86_64_PC32	.text+0x161f1
034c      34c:	e9 00 00 00 00       	jmp    351 <.altinstr_replacement+0x351>	34d: R_X86_64_PC32	.init.text+0xe677
0351      351:	0f ae e8             	lfence
0354      354:	0f 31                	rdtsc
0356      356:	0f 01 f9             	rdtscp
0359      359:	0f ae e8             	lfence
035c      35c:	0f 31                	rdtsc
035e      35e:	0f 01 f9             	rdtscp
0361      361:	0f ae e8             	lfence
0364      364:	0f 31                	rdtsc
0366      366:	0f 01 f9             	rdtscp
0369      369:	f3 48 0f b8 c7       	popcnt %rdi,%rax
036e      36e:	f3 48 0f b8 c7       	popcnt %rdi,%rax
0373      373:	9c                   	pushf
0374      374:	58                   	pop    %rax
0375      375:	fb                   	sti
0376      376:	9c                   	pushf
0377      377:	58                   	pop    %rax
0378      378:	fa                   	cli
0379      379:	9c                   	pushf
037a      37a:	58                   	pop    %rax
037b      37b:	fa                   	cli
037c      37c:	9c                   	pushf
037d      37d:	58                   	pop    %rax
037e      37e:	fa                   	cli
037f      37f:	9c                   	pushf
0380      380:	58                   	pop    %rax
0381      381:	fb                   	sti
0382      382:	e9 00 00 00 00       	jmp    387 <.altinstr_replacement+0x387>	383: R_X86_64_PC32	.init.text+0x13d63
0387      387:	e9 00 00 00 00       	jmp    38c <.altinstr_replacement+0x38c>	388: R_X86_64_PC32	.text+0x3429d
038c      38c:	e9 00 00 00 00       	jmp    391 <.altinstr_replacement+0x391>	38d: R_X86_64_PC32	.text+0x342a8
0391      391:	e9 00 00 00 00       	jmp    396 <.altinstr_replacement+0x396>	392: R_X86_64_PC32	.text+0x3432f
0396      396:	e9 00 00 00 00       	jmp    39b <.altinstr_replacement+0x39b>	397: R_X86_64_PC32	.text+0x3433a
039b      39b:	e9 00 00 00 00       	jmp    3a0 <.altinstr_replacement+0x3a0>	39c: R_X86_64_PC32	.text+0x34e5f
03a0      3a0:	e9 00 00 00 00       	jmp    3a5 <.altinstr_replacement+0x3a5>	3a1: R_X86_64_PC32	.text+0x356d5
03a5      3a5:	e9 00 00 00 00       	jmp    3aa <.altinstr_replacement+0x3aa>	3a6: R_X86_64_PC32	.text+0x35e70
03aa      3aa:	e9 00 00 00 00       	jmp    3af <.altinstr_replacement+0x3af>	3ab: R_X86_64_PC32	.text+0x35d8e
03af      3af:	e9 00 00 00 00       	jmp    3b4 <.altinstr_replacement+0x3b4>	3b0: R_X86_64_PC32	.text+0x35ee0
03b4      3b4:	e9 00 00 00 00       	jmp    3b9 <.altinstr_replacement+0x3b9>	3b5: R_X86_64_PC32	.text+0x35e63
03b9      3b9:	e9 00 00 00 00       	jmp    3be <.altinstr_replacement+0x3be>	3ba: R_X86_64_PC32	.text+0x36239
03be      3be:	e9 00 00 00 00       	jmp    3c3 <.altinstr_replacement+0x3c3>	3bf: R_X86_64_PC32	.text+0x36343
03c3      3c3:	e9 00 00 00 00       	jmp    3c8 <.altinstr_replacement+0x3c8>	3c4: R_X86_64_PC32	.text+0x3634e
03c8      3c8:	e9 00 00 00 00       	jmp    3cd <.altinstr_replacement+0x3cd>	3c9: R_X86_64_PC32	.text+0x363f6
03cd      3cd:	e9 00 00 00 00       	jmp    3d2 <.altinstr_replacement+0x3d2>	3ce: R_X86_64_PC32	.text+0x364b9
03d2      3d2:	e9 00 00 00 00       	jmp    3d7 <.altinstr_replacement+0x3d7>	3d3: R_X86_64_PC32	.text+0x364c7
03d7      3d7:	e9 00 00 00 00       	jmp    3dc <.altinstr_replacement+0x3dc>	3d8: R_X86_64_PC32	.text+0x363f6
03dc      3dc:	e9 00 00 00 00       	jmp    3e1 <.altinstr_replacement+0x3e1>	3dd: R_X86_64_PC32	.text+0x36f3f
03e1      3e1:	e9 00 00 00 00       	jmp    3e6 <.altinstr_replacement+0x3e6>	3e2: R_X86_64_PC32	.text+0x36fcd
03e6      3e6:	e9 00 00 00 00       	jmp    3eb <.altinstr_replacement+0x3eb>	3e7: R_X86_64_PC32	.text+0x36fc2
03eb      3eb:	e9 00 00 00 00       	jmp    3f0 <.altinstr_replacement+0x3f0>	3ec: R_X86_64_PC32	.text+0x36fb7
03f0      3f0:	e9 00 00 00 00       	jmp    3f5 <.altinstr_replacement+0x3f5>	3f1: R_X86_64_PC32	.text+0x373b3
03f5      3f5:	e9 00 00 00 00       	jmp    3fa <.altinstr_replacement+0x3fa>	3f6: R_X86_64_PC32	.text+0x3757d
03fa      3fa:	e9 00 00 00 00       	jmp    3ff <.altinstr_replacement+0x3ff>	3fb: R_X86_64_PC32	.text+0x37743
03ff      3ff:	e9 00 00 00 00       	jmp    404 <.altinstr_replacement+0x404>	400: R_X86_64_PC32	.text+0x379bf
0404      404:	e9 00 00 00 00       	jmp    409 <.altinstr_replacement+0x409>	405: R_X86_64_PC32	.text+0x37c4e
0409      409:	e9 00 00 00 00       	jmp    40e <.altinstr_replacement+0x40e>	40a: R_X86_64_PC32	.text+0x38b81
040e      40e:	e9 00 00 00 00       	jmp    413 <.altinstr_replacement+0x413>	40f: R_X86_64_PC32	.text+0x38cc2
0413      413:	9c                   	pushf
0414      414:	58                   	pop    %rax
0415      415:	fa                   	cli
0416      416:	9c                   	pushf
0417      417:	58                   	pop    %rax
0418      418:	fb                   	sti
0419      419:	9c                   	pushf
041a      41a:	58                   	pop    %rax
041b      41b:	fa                   	cli
041c      41c:	9c                   	pushf
041d      41d:	58                   	pop    %rax
041e      41e:	fb                   	sti
041f      41f:	f3 0f b8 c7          	popcnt %edi,%eax
0423      423:	f3 48 0f b8 c7       	popcnt %rdi,%rax
0428      428:	e9 00 00 00 00       	jmp    42d <.altinstr_replacement+0x42d>	429: R_X86_64_PC32	.text+0x660c1
042d      42d:	e9 00 00 00 00       	jmp    432 <.altinstr_replacement+0x432>	42e: R_X86_64_PC32	.text+0x6611b
0432      432:	e8 00 00 00 00       	call   437 <.altinstr_replacement+0x437>	433: R_X86_64_PLT32	copy_user_generic_string-0x4
0437      437:	e8 00 00 00 00       	call   43c <.altinstr_replacement+0x43c>	438: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
043c      43c:	e8 00 00 00 00       	call   441 <.altinstr_replacement+0x441>	43d: R_X86_64_PLT32	copy_user_generic_string-0x4
0441      441:	e8 00 00 00 00       	call   446 <.altinstr_replacement+0x446>	442: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
0446      446:	48 89 f8             	mov    %rdi,%rax
0449      449:	e8 00 00 00 00       	call   44e <.altinstr_replacement+0x44e>	44a: R_X86_64_PLT32	copy_user_generic_string-0x4
044e      44e:	e8 00 00 00 00       	call   453 <.altinstr_replacement+0x453>	44f: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
0453      453:	e8 00 00 00 00       	call   458 <.altinstr_replacement+0x458>	454: R_X86_64_PLT32	copy_user_generic_string-0x4
0458      458:	e8 00 00 00 00       	call   45d <.altinstr_replacement+0x45d>	459: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
045d      45d:	48 89 f8             	mov    %rdi,%rax
0460      460:	e9 00 00 00 00       	jmp    465 <.altinstr_replacement+0x465>	461: R_X86_64_PC32	.text+0x6dc45
0465      465:	e9 00 00 00 00       	jmp    46a <.altinstr_replacement+0x46a>	466: R_X86_64_PC32	.text+0x6dc8f
046a      46a:	48 89 f8             	mov    %rdi,%rax
046d      46d:	49 be 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r14
0477      477:	e9 00 00 00 00       	jmp    47c <.altinstr_replacement+0x47c>	478: R_X86_64_PC32	.text+0x72a9a
047c      47c:	e9 00 00 00 00       	jmp    481 <.altinstr_replacement+0x481>	47d: R_X86_64_PC32	.text+0x72909
0481      481:	48 89 f8             	mov    %rdi,%rax
0484      484:	48 89 f8             	mov    %rdi,%rax
0487      487:	48 89 f8             	mov    %rdi,%rax
048a      48a:	e8 00 00 00 00       	call   48f <.altinstr_replacement+0x48f>	48b: R_X86_64_PLT32	copy_user_generic_string-0x4
048f      48f:	e8 00 00 00 00       	call   494 <.altinstr_replacement+0x494>	490: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
0494      494:	e9 00 00 00 00       	jmp    499 <.altinstr_replacement+0x499>	495: R_X86_64_PC32	.text+0x7a0fc
0499      499:	e9 00 00 00 00       	jmp    49e <.altinstr_replacement+0x49e>	49a: R_X86_64_PC32	.text+0x79f6b
049e      49e:	9c                   	pushf
049f      49f:	58                   	pop    %rax
04a0      4a0:	fa                   	cli
04a1      4a1:	9c                   	pushf
04a2      4a2:	58                   	pop    %rax
04a3      4a3:	fb                   	sti
04a4      4a4:	e9 00 00 00 00       	jmp    4a9 <.altinstr_replacement+0x4a9>	4a5: R_X86_64_PC32	.text+0x86ea8
04a9      4a9:	e9 00 00 00 00       	jmp    4ae <.altinstr_replacement+0x4ae>	4aa: R_X86_64_PC32	.text+0x86e56
04ae      4ae:	e9 00 00 00 00       	jmp    4b3 <.altinstr_replacement+0x4b3>	4af: R_X86_64_PC32	.text+0x86c3b
04b3      4b3:	e9 00 00 00 00       	jmp    4b8 <.altinstr_replacement+0x4b8>	4b4: R_X86_64_PC32	.text+0x869db
04b8      4b8:	e9 00 00 00 00       	jmp    4bd <.altinstr_replacement+0x4bd>	4b9: R_X86_64_PC32	.text+0x87728
04bd      4bd:	e9 00 00 00 00       	jmp    4c2 <.altinstr_replacement+0x4c2>	4be: R_X86_64_PC32	.text+0x8788a
04c2      4c2:	e9 00 00 00 00       	jmp    4c7 <.altinstr_replacement+0x4c7>	4c3: R_X86_64_PC32	.text+0x87d5d
04c7      4c7:	e9 00 00 00 00       	jmp    4cc <.altinstr_replacement+0x4cc>	4c8: R_X86_64_PC32	.text+0x87c5b
04cc      4cc:	9c                   	pushf
04cd      4cd:	58                   	pop    %rax
04ce      4ce:	fa                   	cli
04cf      4cf:	9c                   	pushf
04d0      4d0:	58                   	pop    %rax
04d1      4d1:	fb                   	sti
04d2      4d2:	0f ae e8             	lfence
04d5      4d5:	0f 31                	rdtsc
04d7      4d7:	0f 01 f9             	rdtscp
04da      4da:	0f ae e8             	lfence
04dd      4dd:	0f 31                	rdtsc
04df      4df:	0f 01 f9             	rdtscp
04e2      4e2:	0f 09                	wbinvd
04e4      4e4:	0f 09                	wbinvd
04e6      4e6:	9c                   	pushf
04e7      4e7:	58                   	pop    %rax
04e8      4e8:	fa                   	cli
04e9      4e9:	9c                   	pushf
04ea      4ea:	58                   	pop    %rax
04eb      4eb:	fb                   	sti
04ec      4ec:	0f 01 cb             	stac
04ef      4ef:	0f ae e8             	lfence
04f2      4f2:	0f 01 cb             	stac
04f5      4f5:	0f ae e8             	lfence
04f8      4f8:	0f 01 cb             	stac
04fb      4fb:	0f ae e8             	lfence
04fe      4fe:	0f 01 ca             	clac
0501      501:	0f 01 cb             	stac
0504      504:	0f ae e8             	lfence
0507      507:	0f 01 ca             	clac
050a      50a:	9c                   	pushf
050b      50b:	58                   	pop    %rax
050c      50c:	fa                   	cli
050d      50d:	9c                   	pushf
050e      50e:	58                   	pop    %rax
050f      50f:	fb                   	sti
0510      510:	9c                   	pushf
0511      511:	58                   	pop    %rax
0512      512:	fb                   	sti
0513      513:	9c                   	pushf
0514      514:	58                   	pop    %rax
0515      515:	fa                   	cli
0516      516:	9c                   	pushf
0517      517:	58                   	pop    %rax
0518      518:	fb                   	sti
0519      519:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
0523      523:	0f 01 cb             	stac
0526      526:	0f ae e8             	lfence
0529      529:	0f 01 ca             	clac
052c      52c:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
0536      536:	0f 01 cb             	stac
0539      539:	0f ae e8             	lfence
053c      53c:	0f 01 ca             	clac
053f      53f:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
0549      549:	0f 01 cb             	stac
054c      54c:	0f ae e8             	lfence
054f      54f:	e9 00 00 00 00       	jmp    554 <.altinstr_replacement+0x554>	550: R_X86_64_PC32	.text+0xc6727
0554      554:	e9 00 00 00 00       	jmp    559 <.altinstr_replacement+0x559>	555: R_X86_64_PC32	.text+0xc673f
0559      559:	e9 00 00 00 00       	jmp    55e <.altinstr_replacement+0x55e>	55a: R_X86_64_PC32	.text+0xc6c92
055e      55e:	e9 00 00 00 00       	jmp    563 <.altinstr_replacement+0x563>	55f: R_X86_64_PC32	.text+0xc6c92
0563      563:	e9 00 00 00 00       	jmp    568 <.altinstr_replacement+0x568>	564: R_X86_64_PC32	.text+0xcfb98
0568      568:	9c                   	pushf
0569      569:	58                   	pop    %rax
056a      56a:	fa                   	cli
056b      56b:	fb                   	sti
056c      56c:	fb                   	sti
056d      56d:	9c                   	pushf
056e      56e:	58                   	pop    %rax
056f      56f:	fa                   	cli
0570      570:	fb                   	sti
0571      571:	9c                   	pushf
0572      572:	58                   	pop    %rax
0573      573:	e8 00 00 00 00       	call   578 <.altinstr_replacement+0x578>	574: R_X86_64_PLT32	__x86_indirect_thunk_r12-0x4
0578      578:	0f ae e8             	lfence
057b      57b:	41 ff d4             	call   *%r12
057e      57e:	e8 00 00 00 00       	call   583 <.altinstr_replacement+0x583>	57f: R_X86_64_PLT32	__x86_indirect_thunk_rsi-0x4
0583      583:	0f ae e8             	lfence
0586      586:	ff d6                	call   *%rsi
0588      588:	e8 00 00 00 00       	call   58d <.altinstr_replacement+0x58d>	589: R_X86_64_PLT32	__x86_indirect_thunk_r13-0x4
058d      58d:	0f ae e8             	lfence
0590      590:	41 ff d5             	call   *%r13
0593      593:	e8 00 00 00 00       	call   598 <.altinstr_replacement+0x598>	594: R_X86_64_PLT32	__x86_indirect_thunk_r13-0x4
0598      598:	0f ae e8             	lfence
059b      59b:	41 ff d5             	call   *%r13
059e      59e:	e8 00 00 00 00       	call   5a3 <.altinstr_replacement+0x5a3>	59f: R_X86_64_PLT32	__x86_indirect_thunk_rax-0x4
05a3      5a3:	0f ae e8             	lfence
05a6      5a6:	ff d0                	call   *%rax
05a8      5a8:	e8 00 00 00 00       	call   5ad <.altinstr_replacement+0x5ad>	5a9: R_X86_64_PLT32	__x86_indirect_thunk_r13-0x4
05ad      5ad:	0f ae e8             	lfence
05b0      5b0:	41 ff d5             	call   *%r13
05b3      5b3:	f3 0f b8 c7          	popcnt %edi,%eax
05b7      5b7:	9c                   	pushf
05b8      5b8:	58                   	pop    %rax
05b9      5b9:	f3 0f b8 c7          	popcnt %edi,%eax
05bd      5bd:	f3 0f b8 c7          	popcnt %edi,%eax
05c1      5c1:	9c                   	pushf
05c2      5c2:	58                   	pop    %rax
05c3      5c3:	9c                   	pushf
05c4      5c4:	58                   	pop    %rax
05c5      5c5:	fa                   	cli
05c6      5c6:	9c                   	pushf
05c7      5c7:	58                   	pop    %rax
05c8      5c8:	fb                   	sti
05c9      5c9:	9c                   	pushf
05ca      5ca:	58                   	pop    %rax
05cb      5cb:	e9 00 00 00 00       	jmp    5d0 <.altinstr_replacement+0x5d0>	5cc: R_X86_64_PC32	.text+0x1176a8
05d0      5d0:	e9 00 00 00 00       	jmp    5d5 <.altinstr_replacement+0x5d5>	5d1: R_X86_64_PC32	.text+0x11765e
05d5      5d5:	e9 00 00 00 00       	jmp    5da <.altinstr_replacement+0x5da>	5d6: R_X86_64_PC32	.text+0x117e2d
05da      5da:	e9 00 00 00 00       	jmp    5df <.altinstr_replacement+0x5df>	5db: R_X86_64_PC32	.text+0x117da9
05df      5df:	e9 00 00 00 00       	jmp    5e4 <.altinstr_replacement+0x5e4>	5e0: R_X86_64_PC32	.text+0x1176ff
05e4      5e4:	f3 48 0f b8 c7       	popcnt %rdi,%rax
05e9      5e9:	f3 48 0f b8 c7       	popcnt %rdi,%rax
05ee      5ee:	e9 00 00 00 00       	jmp    5f3 <.altinstr_replacement+0x5f3>	5ef: R_X86_64_PC32	.text+0x12e49e
05f3      5f3:	48 89 f8             	mov    %rdi,%rax
05f6      5f6:	9c                   	pushf
05f7      5f7:	58                   	pop    %rax
05f8      5f8:	fa                   	cli
05f9      5f9:	0f 01 cb             	stac
05fc      5fc:	0f ae e8             	lfence
05ff      5ff:	0f 01 ca             	clac
0602      602:	0f 01 ca             	clac
0605      605:	0f 01 cb             	stac
0608      608:	0f ae e8             	lfence
060b      60b:	0f 01 ca             	clac
060e      60e:	0f 01 ca             	clac
0611      611:	0f 01 cb             	stac
0614      614:	0f ae e8             	lfence
0617      617:	0f 01 ca             	clac
061a      61a:	0f 01 ca             	clac
061d      61d:	fb                   	sti
061e      61e:	48 89 f8             	mov    %rdi,%rax
0621      621:	9c                   	pushf
0622      622:	58                   	pop    %rax
0623      623:	fa                   	cli
0624      624:	e9 00 00 00 00       	jmp    629 <.altinstr_replacement+0x629>	625: R_X86_64_PC32	.text+0x14131d
0629      629:	9c                   	pushf
062a      62a:	58                   	pop    %rax
062b      62b:	fb                   	sti
062c      62c:	48 89 f8             	mov    %rdi,%rax
062f      62f:	48 89 f8             	mov    %rdi,%rax
0632      632:	48 89 f8             	mov    %rdi,%rax
0635      635:	9c                   	pushf
0636      636:	58                   	pop    %rax
0637      637:	fa                   	cli
0638      638:	fb                   	sti
0639      639:	e9 00 00 00 00       	jmp    63e <.altinstr_replacement+0x63e>	63a: R_X86_64_PC32	.text+0x15de06
063e      63e:	e9 00 00 00 00       	jmp    643 <.altinstr_replacement+0x643>	63f: R_X86_64_PC32	.text+0x15dcc7
0643      643:	48 89 f8             	mov    %rdi,%rax
0646      646:	e9 00 00 00 00       	jmp    64b <.altinstr_replacement+0x64b>	647: R_X86_64_PC32	.noinstr.text+0x1671
064b      64b:	e8 00 00 00 00       	call   650 <.altinstr_replacement+0x650>	64c: R_X86_64_PLT32	copy_user_generic_string-0x4
0650      650:	e8 00 00 00 00       	call   655 <.altinstr_replacement+0x655>	651: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
0655      655:	e8 00 00 00 00       	call   65a <.altinstr_replacement+0x65a>	656: R_X86_64_PLT32	copy_user_generic_string-0x4
065a      65a:	e8 00 00 00 00       	call   65f <.altinstr_replacement+0x65f>	65b: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
065f      65f:	e8 00 00 00 00       	call   664 <.altinstr_replacement+0x664>	660: R_X86_64_PLT32	copy_user_generic_string-0x4
0664      664:	e8 00 00 00 00       	call   669 <.altinstr_replacement+0x669>	665: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
0669      669:	9c                   	pushf
066a      66a:	58                   	pop    %rax
066b      66b:	fa                   	cli
066c      66c:	9c                   	pushf
066d      66d:	58                   	pop    %rax
066e      66e:	fb                   	sti
066f      66f:	9c                   	pushf
0670      670:	58                   	pop    %rax
0671      671:	fa                   	cli
0672      672:	9c                   	pushf
0673      673:	58                   	pop    %rax
0674      674:	fb                   	sti
0675      675:	9c                   	pushf
0676      676:	58                   	pop    %rax
0677      677:	e9 00 00 00 00       	jmp    67c <.altinstr_replacement+0x67c>	678: R_X86_64_PC32	.text+0x17f468
067c      67c:	9c                   	pushf
067d      67d:	58                   	pop    %rax
067e      67e:	fa                   	cli
067f      67f:	fb                   	sti
0680      680:	0f 30                	wrmsr
0682      682:	e8 00 00 00 00       	call   687 <.altinstr_replacement+0x687>	683: R_X86_64_PLT32	copy_user_generic_string-0x4
0687      687:	e8 00 00 00 00       	call   68c <.altinstr_replacement+0x68c>	688: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
068c      68c:	0f 20 d8             	mov    %cr3,%rax
068f      68f:	e9 00 00 00 00       	jmp    694 <.altinstr_replacement+0x694>	690: R_X86_64_PC32	.noinstr.text+0x1af2
0694      694:	e9 00 00 00 00       	jmp    699 <.altinstr_replacement+0x699>	695: R_X86_64_PC32	.noinstr.text+0x1afb
0699      699:	0f ae e8             	lfence
069c      69c:	48 c7 c1 10 00 00 00 	mov    $0x10,%rcx
06a3      6a3:	e8 01 00 00 00       	call   6a9 <.altinstr_replacement+0x6a9>
06a8      6a8:	cc                   	int3
06a9      6a9:	e8 01 00 00 00       	call   6af <.altinstr_replacement+0x6af>
06ae      6ae:	cc                   	int3
06af      6af:	48 83 c4 10          	add    $0x10,%rsp
06b3      6b3:	48 ff c9             	dec    %rcx
06b6      6b6:	75 eb                	jne    6a3 <.altinstr_replacement+0x6a3>
06b8      6b8:	0f ae e8             	lfence
06bb      6bb:	e8 01 00 00 00       	call   6c1 <.altinstr_replacement+0x6c1>
06c0      6c0:	cc                   	int3
06c1      6c1:	48 83 c4 08          	add    $0x8,%rsp
06c5      6c5:	0f ae e8             	lfence
06c8      6c8:	9c                   	pushf
06c9      6c9:	58                   	pop    %rax
06ca      6ca:	fa                   	cli
06cb      6cb:	fb                   	sti
06cc      6cc:	fb                   	sti
06cd      6cd:	fb                   	sti
06ce      6ce:	9c                   	pushf
06cf      6cf:	58                   	pop    %rax
06d0      6d0:	fa                   	cli
06d1      6d1:	9c                   	pushf
06d2      6d2:	58                   	pop    %rax
06d3      6d3:	fb                   	sti
06d4      6d4:	9c                   	pushf
06d5      6d5:	58                   	pop    %rax
06d6      6d6:	fa                   	cli
06d7      6d7:	9c                   	pushf
06d8      6d8:	58                   	pop    %rax
06d9      6d9:	fb                   	sti
06da      6da:	e8 00 00 00 00       	call   6df <.altinstr_replacement+0x6df>	6db: R_X86_64_PLT32	copy_user_generic_string-0x4
06df      6df:	e8 00 00 00 00       	call   6e4 <.altinstr_replacement+0x6e4>	6e0: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
06e4      6e4:	e9 00 00 00 00       	jmp    6e9 <.altinstr_replacement+0x6e9>	6e5: R_X86_64_PC32	.text.unlikely+0x1b2ca
06e9      6e9:	e9 00 00 00 00       	jmp    6ee <.altinstr_replacement+0x6ee>	6ea: R_X86_64_PC32	.text+0x1e68be
06ee      6ee:	e9 00 00 00 00       	jmp    6f3 <.altinstr_replacement+0x6f3>	6ef: R_X86_64_PC32	.text+0x1e7e28
06f3      6f3:	e9 00 00 00 00       	jmp    6f8 <.altinstr_replacement+0x6f8>	6f4: R_X86_64_PC32	.text+0x1e7f60
06f8      6f8:	e9 00 00 00 00       	jmp    6fd <.altinstr_replacement+0x6fd>	6f9: R_X86_64_PC32	.text+0x1e8138
06fd      6fd:	e8 00 00 00 00       	call   702 <.altinstr_replacement+0x702>	6fe: R_X86_64_PLT32	clear_page_rep-0x4
0702      702:	e8 00 00 00 00       	call   707 <.altinstr_replacement+0x707>	703: R_X86_64_PLT32	clear_page_erms-0x4
0707      707:	0f 30                	wrmsr
0709      709:	e9 00 00 00 00       	jmp    70e <.altinstr_replacement+0x70e>	70a: R_X86_64_PC32	.text+0x1ec22e
070e      70e:	e9 00 00 00 00       	jmp    713 <.altinstr_replacement+0x713>	70f: R_X86_64_PC32	.text+0x1ede66
0713      713:	e9 00 00 00 00       	jmp    718 <.altinstr_replacement+0x718>	714: R_X86_64_PC32	.text+0x1ee260
0718      718:	e9 00 00 00 00       	jmp    71d <.altinstr_replacement+0x71d>	719: R_X86_64_PC32	.text+0x1f0133
071d      71d:	e9 00 00 00 00       	jmp    722 <.altinstr_replacement+0x722>	71e: R_X86_64_PC32	.text+0x1f3a72
0722      722:	e9 00 00 00 00       	jmp    727 <.altinstr_replacement+0x727>	723: R_X86_64_PC32	.text+0x1f3af1
0727      727:	e9 00 00 00 00       	jmp    72c <.altinstr_replacement+0x72c>	728: R_X86_64_PC32	.text+0x1f7da1
072c      72c:	e9 00 00 00 00       	jmp    731 <.altinstr_replacement+0x731>	72d: R_X86_64_PC32	.text+0x1f7ce8
0731      731:	e9 00 00 00 00       	jmp    736 <.altinstr_replacement+0x736>	732: R_X86_64_PC32	.text+0x1f81dd
0736      736:	48 c7 c0 10 00 00 00 	mov    $0x10,%rax
073d      73d:	e8 01 00 00 00       	call   743 <.altinstr_replacement+0x743>
0742      742:	cc                   	int3
0743      743:	e8 01 00 00 00       	call   749 <.altinstr_replacement+0x749>
0748      748:	cc                   	int3
0749      749:	48 83 c4 10          	add    $0x10,%rsp
074d      74d:	48 ff c8             	dec    %rax
0750      750:	75 eb                	jne    73d <.altinstr_replacement+0x73d>
0752      752:	0f ae e8             	lfence
0755      755:	e8 01 00 00 00       	call   75b <.altinstr_replacement+0x75b>
075a      75a:	cc                   	int3
075b      75b:	48 83 c4 08          	add    $0x8,%rsp
075f      75f:	0f ae e8             	lfence
0762      762:	e8 00 00 00 00       	call   767 <.altinstr_replacement+0x767>	763: R_X86_64_PLT32	zen_untrain_ret-0x4
0767      767:	e8 00 00 00 00       	call   76c <.altinstr_replacement+0x76c>	768: R_X86_64_PLT32	entry_ibpb-0x4
076c      76c:	48 c7 c0 10 00 00 00 	mov    $0x10,%rax
0773      773:	e8 01 00 00 00       	call   779 <.altinstr_replacement+0x779>
0778      778:	cc                   	int3
0779      779:	e8 01 00 00 00       	call   77f <.altinstr_replacement+0x77f>
077e      77e:	cc                   	int3
077f      77f:	48 83 c4 10          	add    $0x10,%rsp
0783      783:	48 ff c8             	dec    %rax
0786      786:	75 eb                	jne    773 <.altinstr_replacement+0x773>
0788      788:	0f ae e8             	lfence
078b      78b:	e8 01 00 00 00       	call   791 <.altinstr_replacement+0x791>
0790      790:	cc                   	int3
0791      791:	48 83 c4 08          	add    $0x8,%rsp
0795      795:	0f ae e8             	lfence
0798      798:	e8 00 00 00 00       	call   79d <.altinstr_replacement+0x79d>	799: R_X86_64_PLT32	zen_untrain_ret-0x4
079d      79d:	e8 00 00 00 00       	call   7a2 <.altinstr_replacement+0x7a2>	79e: R_X86_64_PLT32	entry_ibpb-0x4
07a2      7a2:	e9 00 00 00 00       	jmp    7a7 <.altinstr_replacement+0x7a7>	7a3: R_X86_64_PC32	.text+0x2176a5
07a7      7a7:	e8 00 00 00 00       	call   7ac <.altinstr_replacement+0x7ac>	7a8: R_X86_64_PLT32	clear_page_rep-0x4
07ac      7ac:	e8 00 00 00 00       	call   7b1 <.altinstr_replacement+0x7b1>	7ad: R_X86_64_PLT32	clear_page_erms-0x4
07b1      7b1:	48 89 f8             	mov    %rdi,%rax
07b4      7b4:	e9 00 00 00 00       	jmp    7b9 <.altinstr_replacement+0x7b9>	7b5: R_X86_64_PC32	.init.text+0x24dc1
07b9      7b9:	e9 00 00 00 00       	jmp    7be <.altinstr_replacement+0x7be>	7ba: R_X86_64_PC32	.init.text+0x260ea
07be      7be:	9c                   	pushf
07bf      7bf:	58                   	pop    %rax
07c0      7c0:	48 89 f8             	mov    %rdi,%rax
07c3      7c3:	48 89 f8             	mov    %rdi,%rax
07c6      7c6:	48 89 f8             	mov    %rdi,%rax
07c9      7c9:	48 89 f8             	mov    %rdi,%rax
07cc      7cc:	48 89 f8             	mov    %rdi,%rax
07cf      7cf:	48 89 f8             	mov    %rdi,%rax
07d2      7d2:	48 89 f8             	mov    %rdi,%rax
07d5      7d5:	48 89 f8             	mov    %rdi,%rax
07d8      7d8:	48 89 f8             	mov    %rdi,%rax
07db      7db:	48 89 f8             	mov    %rdi,%rax
07de      7de:	48 89 f8             	mov    %rdi,%rax
07e1      7e1:	9c                   	pushf
07e2      7e2:	58                   	pop    %rax
07e3      7e3:	fa                   	cli
07e4      7e4:	9c                   	pushf
07e5      7e5:	58                   	pop    %rax
07e6      7e6:	fb                   	sti
07e7      7e7:	9c                   	pushf
07e8      7e8:	58                   	pop    %rax
07e9      7e9:	fa                   	cli
07ea      7ea:	0f 20 d8             	mov    %cr3,%rax
07ed      7ed:	48 89 f8             	mov    %rdi,%rax
07f0      7f0:	48 89 f8             	mov    %rdi,%rax
07f3      7f3:	48 89 f8             	mov    %rdi,%rax
07f6      7f6:	48 89 f8             	mov    %rdi,%rax
07f9      7f9:	48 89 f8             	mov    %rdi,%rax
07fc      7fc:	48 89 f8             	mov    %rdi,%rax
07ff      7ff:	48 89 f8             	mov    %rdi,%rax
0802      802:	48 be 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rsi
080c      80c:	e9 00 00 00 00       	jmp    811 <.altinstr_replacement+0x811>	80d: R_X86_64_PC32	.init.text+0x298ea
0811      811:	48 89 f8             	mov    %rdi,%rax
0814      814:	e9 00 00 00 00       	jmp    819 <.altinstr_replacement+0x819>	815: R_X86_64_PC32	.text+0x2284b0
0819      819:	48 89 f8             	mov    %rdi,%rax
081c      81c:	48 89 f8             	mov    %rdi,%rax
081f      81f:	48 89 f8             	mov    %rdi,%rax
0822      822:	e9 00 00 00 00       	jmp    827 <.altinstr_replacement+0x827>	823: R_X86_64_PC32	.text+0x22a172
0827      827:	e9 00 00 00 00       	jmp    82c <.altinstr_replacement+0x82c>	828: R_X86_64_PC32	.text+0x22a1e5
082c      82c:	48 89 f8             	mov    %rdi,%rax
082f      82f:	48 89 f8             	mov    %rdi,%rax
0832      832:	9c                   	pushf
0833      833:	58                   	pop    %rax
0834      834:	fb                   	sti
0835      835:	9c                   	pushf
0836      836:	58                   	pop    %rax
0837      837:	fa                   	cli
0838      838:	48 be 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rsi
0842      842:	48 be 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rsi
084c      84c:	9c                   	pushf
084d      84d:	58                   	pop    %rax
084e      84e:	9c                   	pushf
084f      84f:	58                   	pop    %rax
0850      850:	48 89 f8             	mov    %rdi,%rax
0853      853:	e8 00 00 00 00       	call   858 <.altinstr_replacement+0x858>	854: R_X86_64_PLT32	clear_page_rep-0x4
0858      858:	e8 00 00 00 00       	call   85d <.altinstr_replacement+0x85d>	859: R_X86_64_PLT32	clear_page_erms-0x4
085d      85d:	e8 00 00 00 00       	call   862 <.altinstr_replacement+0x862>	85e: R_X86_64_PLT32	clear_page_rep-0x4
0862      862:	e8 00 00 00 00       	call   867 <.altinstr_replacement+0x867>	863: R_X86_64_PLT32	clear_page_erms-0x4
0867      867:	e8 00 00 00 00       	call   86c <.altinstr_replacement+0x86c>	868: R_X86_64_PLT32	clear_page_rep-0x4
086c      86c:	e8 00 00 00 00       	call   871 <.altinstr_replacement+0x871>	86d: R_X86_64_PLT32	clear_page_erms-0x4
0871      871:	e9 00 00 00 00       	jmp    876 <.altinstr_replacement+0x876>	872: R_X86_64_PC32	.init.text+0x2afa8
0876      876:	e9 00 00 00 00       	jmp    87b <.altinstr_replacement+0x87b>	877: R_X86_64_PC32	.init.text+0x2b169
087b      87b:	48 89 f8             	mov    %rdi,%rax
087e      87e:	48 89 f8             	mov    %rdi,%rax
0881      881:	48 89 f8             	mov    %rdi,%rax
0884      884:	e8 00 00 00 00       	call   889 <.altinstr_replacement+0x889>	885: R_X86_64_PLT32	clear_page_rep-0x4
0889      889:	e8 00 00 00 00       	call   88e <.altinstr_replacement+0x88e>	88a: R_X86_64_PLT32	clear_page_erms-0x4
088e      88e:	e8 00 00 00 00       	call   893 <.altinstr_replacement+0x893>	88f: R_X86_64_PLT32	clear_page_rep-0x4
0893      893:	e8 00 00 00 00       	call   898 <.altinstr_replacement+0x898>	894: R_X86_64_PLT32	clear_page_erms-0x4
0898      898:	9c                   	pushf
0899      899:	58                   	pop    %rax
089a      89a:	9c                   	pushf
089b      89b:	58                   	pop    %rax
089c      89c:	fa                   	cli
089d      89d:	e8 00 00 00 00       	call   8a2 <.altinstr_replacement+0x8a2>	89e: R_X86_64_PLT32	__x86_indirect_thunk_rax-0x4
08a2      8a2:	0f ae e8             	lfence
08a5      8a5:	ff d0                	call   *%rax
08a7      8a7:	9c                   	pushf
08a8      8a8:	58                   	pop    %rax
08a9      8a9:	fb                   	sti
08aa      8aa:	9c                   	pushf
08ab      8ab:	58                   	pop    %rax
08ac      8ac:	9c                   	pushf
08ad      8ad:	58                   	pop    %rax
08ae      8ae:	9c                   	pushf
08af      8af:	58                   	pop    %rax
08b0      8b0:	48 89 f8             	mov    %rdi,%rax
08b3      8b3:	48 89 f8             	mov    %rdi,%rax
08b6      8b6:	48 89 f8             	mov    %rdi,%rax
08b9      8b9:	48 89 f8             	mov    %rdi,%rax
08bc      8bc:	48 89 f8             	mov    %rdi,%rax
08bf      8bf:	48 89 f8             	mov    %rdi,%rax
08c2      8c2:	48 89 f8             	mov    %rdi,%rax
08c5      8c5:	fb                   	sti
08c6      8c6:	0f 22 df             	mov    %rdi,%cr3
08c9      8c9:	9c                   	pushf
08ca      8ca:	58                   	pop    %rax
08cb      8cb:	fa                   	cli
08cc      8cc:	fb                   	sti
08cd      8cd:	0f 22 df             	mov    %rdi,%cr3
08d0      8d0:	9c                   	pushf
08d1      8d1:	58                   	pop    %rax
08d2      8d2:	fa                   	cli
08d3      8d3:	e8 00 00 00 00       	call   8d8 <.altinstr_replacement+0x8d8>	8d4: R_X86_64_PLT32	__x86_indirect_thunk_r15-0x4
08d8      8d8:	0f ae e8             	lfence
08db      8db:	41 ff d7             	call   *%r15
08de      8de:	9c                   	pushf
08df      8df:	58                   	pop    %rax
08e0      8e0:	fb                   	sti
08e1      8e1:	e9 00 00 00 00       	jmp    8e6 <.altinstr_replacement+0x8e6>	8e2: R_X86_64_PC32	.init.text+0x30367
08e6      8e6:	e8 00 00 00 00       	call   8eb <.altinstr_replacement+0x8eb>	8e7: R_X86_64_PLT32	__x86_indirect_thunk_r15-0x4
08eb      8eb:	0f ae e8             	lfence
08ee      8ee:	41 ff d7             	call   *%r15
08f1      8f1:	e8 00 00 00 00       	call   8f6 <.altinstr_replacement+0x8f6>	8f2: R_X86_64_PLT32	__x86_indirect_thunk_r12-0x4
08f6      8f6:	0f ae e8             	lfence
08f9      8f9:	41 ff d4             	call   *%r12
08fc      8fc:	9c                   	pushf
08fd      8fd:	58                   	pop    %rax
08fe      8fe:	fa                   	cli
08ff      8ff:	e8 00 00 00 00       	call   904 <.altinstr_replacement+0x904>	900: R_X86_64_PLT32	__x86_indirect_thunk_rbp-0x4
0904      904:	0f ae e8             	lfence
0907      907:	ff d5                	call   *%rbp
0909      909:	e8 00 00 00 00       	call   90e <.altinstr_replacement+0x90e>	90a: R_X86_64_PLT32	__x86_indirect_thunk_rbx-0x4
090e      90e:	0f ae e8             	lfence
0911      911:	ff d3                	call   *%rbx
0913      913:	9c                   	pushf
0914      914:	58                   	pop    %rax
0915      915:	fb                   	sti
0916      916:	9c                   	pushf
0917      917:	58                   	pop    %rax
0918      918:	9c                   	pushf
0919      919:	58                   	pop    %rax
091a      91a:	fb                   	sti
091b      91b:	9c                   	pushf
091c      91c:	58                   	pop    %rax
091d      91d:	fb                   	sti
091e      91e:	9c                   	pushf
091f      91f:	58                   	pop    %rax
0920      920:	fa                   	cli
0921      921:	9c                   	pushf
0922      922:	58                   	pop    %rax
0923      923:	e8 00 00 00 00       	call   928 <.altinstr_replacement+0x928>	924: R_X86_64_PLT32	__x86_indirect_thunk_r12-0x4
0928      928:	0f ae e8             	lfence
092b      92b:	41 ff d4             	call   *%r12
092e      92e:	9c                   	pushf
092f      92f:	58                   	pop    %rax
0930      930:	fb                   	sti
0931      931:	fb                   	sti
0932      932:	9c                   	pushf
0933      933:	58                   	pop    %rax
0934      934:	9c                   	pushf
0935      935:	58                   	pop    %rax
0936      936:	fa                   	cli
0937      937:	e8 00 00 00 00       	call   93c <.altinstr_replacement+0x93c>	938: R_X86_64_PLT32	__x86_indirect_thunk_r13-0x4
093c      93c:	0f ae e8             	lfence
093f      93f:	41 ff d5             	call   *%r13
0942      942:	9c                   	pushf
0943      943:	58                   	pop    %rax
0944      944:	fb                   	sti
0945      945:	9c                   	pushf
0946      946:	58                   	pop    %rax
0947      947:	fb                   	sti
0948      948:	9c                   	pushf
0949      949:	58                   	pop    %rax
094a      94a:	fa                   	cli
094b      94b:	e8 00 00 00 00       	call   950 <.altinstr_replacement+0x950>	94c: R_X86_64_PLT32	__x86_indirect_thunk_r12-0x4
0950      950:	0f ae e8             	lfence
0953      953:	41 ff d4             	call   *%r12
0956      956:	9c                   	pushf
0957      957:	58                   	pop    %rax
0958      958:	fb                   	sti
0959      959:	9c                   	pushf
095a      95a:	58                   	pop    %rax
095b      95b:	fa                   	cli
095c      95c:	9c                   	pushf
095d      95d:	58                   	pop    %rax
095e      95e:	fb                   	sti
095f      95f:	e8 00 00 00 00       	call   964 <.altinstr_replacement+0x964>	960: R_X86_64_PLT32	__x86_indirect_thunk_r12-0x4
0964      964:	0f ae e8             	lfence
0967      967:	41 ff d4             	call   *%r12
096a      96a:	9c                   	pushf
096b      96b:	58                   	pop    %rax
096c      96c:	fb                   	sti
096d      96d:	9c                   	pushf
096e      96e:	58                   	pop    %rax
096f      96f:	fa                   	cli
0970      970:	9c                   	pushf
0971      971:	58                   	pop    %rax
0972      972:	fb                   	sti
0973      973:	9c                   	pushf
0974      974:	58                   	pop    %rax
0975      975:	9c                   	pushf
0976      976:	58                   	pop    %rax
0977      977:	fa                   	cli
0978      978:	9c                   	pushf
0979      979:	58                   	pop    %rax
097a      97a:	fb                   	sti
097b      97b:	9c                   	pushf
097c      97c:	58                   	pop    %rax
097d      97d:	9c                   	pushf
097e      97e:	58                   	pop    %rax
097f      97f:	fa                   	cli
0980      980:	9c                   	pushf
0981      981:	58                   	pop    %rax
0982      982:	fb                   	sti
0983      983:	9c                   	pushf
0984      984:	58                   	pop    %rax
0985      985:	fb                   	sti
0986      986:	e9 00 00 00 00       	jmp    98b <.altinstr_replacement+0x98b>	987: R_X86_64_PC32	.text+0x248511
098b      98b:	9c                   	pushf
098c      98c:	58                   	pop    %rax
098d      98d:	fa                   	cli
098e      98e:	e8 00 00 00 00       	call   993 <.altinstr_replacement+0x993>	98f: R_X86_64_PLT32	__x86_indirect_thunk_r14-0x4
0993      993:	0f ae e8             	lfence
0996      996:	41 ff d6             	call   *%r14
0999      999:	9c                   	pushf
099a      99a:	58                   	pop    %rax
099b      99b:	fb                   	sti
099c      99c:	9c                   	pushf
099d      99d:	58                   	pop    %rax
099e      99e:	fb                   	sti
099f      99f:	9c                   	pushf
09a0      9a0:	58                   	pop    %rax
09a1      9a1:	fa                   	cli
09a2      9a2:	9c                   	pushf
09a3      9a3:	58                   	pop    %rax
09a4      9a4:	e8 00 00 00 00       	call   9a9 <.altinstr_replacement+0x9a9>	9a5: R_X86_64_PLT32	__x86_indirect_thunk_r13-0x4
09a9      9a9:	0f ae e8             	lfence
09ac      9ac:	41 ff d5             	call   *%r13
09af      9af:	9c                   	pushf
09b0      9b0:	58                   	pop    %rax
09b1      9b1:	fb                   	sti
09b2      9b2:	e8 00 00 00 00       	call   9b7 <.altinstr_replacement+0x9b7>	9b3: R_X86_64_PLT32	__x86_indirect_thunk_rax-0x4
09b7      9b7:	0f ae e8             	lfence
09ba      9ba:	ff d0                	call   *%rax
09bc      9bc:	41 87 b4 24 00 c0 5f ff 	xchg   %esi,-0xa04000(%r12)
09c4      9c4:	e8 00 00 00 00       	call   9c9 <.altinstr_replacement+0x9c9>	9c5: R_X86_64_PLT32	__x86_indirect_thunk_rbx-0x4
09c9      9c9:	0f ae e8             	lfence
09cc      9cc:	ff d3                	call   *%rbx
09ce      9ce:	9c                   	pushf
09cf      9cf:	58                   	pop    %rax
09d0      9d0:	fa                   	cli
09d1      9d1:	e8 00 00 00 00       	call   9d6 <.altinstr_replacement+0x9d6>	9d2: R_X86_64_PLT32	__x86_indirect_thunk_r14-0x4
09d6      9d6:	0f ae e8             	lfence
09d9      9d9:	41 ff d6             	call   *%r14
09dc      9dc:	9c                   	pushf
09dd      9dd:	58                   	pop    %rax
09de      9de:	fb                   	sti
09df      9df:	9c                   	pushf
09e0      9e0:	58                   	pop    %rax
09e1      9e1:	fa                   	cli
09e2      9e2:	e8 00 00 00 00       	call   9e7 <.altinstr_replacement+0x9e7>	9e3: R_X86_64_PLT32	__x86_indirect_thunk_r13-0x4
09e7      9e7:	0f ae e8             	lfence
09ea      9ea:	41 ff d5             	call   *%r13
09ed      9ed:	9c                   	pushf
09ee      9ee:	58                   	pop    %rax
09ef      9ef:	fb                   	sti
09f0      9f0:	9c                   	pushf
09f1      9f1:	58                   	pop    %rax
09f2      9f2:	fa                   	cli
09f3      9f3:	e8 00 00 00 00       	call   9f8 <.altinstr_replacement+0x9f8>	9f4: R_X86_64_PLT32	__x86_indirect_thunk_rbp-0x4
09f8      9f8:	0f ae e8             	lfence
09fb      9fb:	ff d5                	call   *%rbp
09fd      9fd:	9c                   	pushf
09fe      9fe:	58                   	pop    %rax
09ff      9ff:	fb                   	sti
0a00      a00:	9c                   	pushf
0a01      a01:	58                   	pop    %rax
0a02      a02:	fa                   	cli
0a03      a03:	9c                   	pushf
0a04      a04:	58                   	pop    %rax
0a05      a05:	fb                   	sti
0a06      a06:	9c                   	pushf
0a07      a07:	58                   	pop    %rax
0a08      a08:	fa                   	cli
0a09      a09:	9c                   	pushf
0a0a      a0a:	58                   	pop    %rax
0a0b      a0b:	fb                   	sti
0a0c      a0c:	0f 22 df             	mov    %rdi,%cr3
0a0f      a0f:	e9 00 00 00 00       	jmp    a14 <.altinstr_replacement+0xa14>	a10: R_X86_64_PC32	.noinstr.text+0x25a9
0a14      a14:	9c                   	pushf
0a15      a15:	58                   	pop    %rax
0a16      a16:	fa                   	cli
0a17      a17:	e9 00 00 00 00       	jmp    a1c <.altinstr_replacement+0xa1c>	a18: R_X86_64_PC32	.text+0x24bf79
0a1c      a1c:	9c                   	pushf
0a1d      a1d:	58                   	pop    %rax
0a1e      a1e:	fb                   	sti
0a1f      a1f:	e9 00 00 00 00       	jmp    a24 <.altinstr_replacement+0xa24>	a20: R_X86_64_PC32	.noinstr.text+0x2626
0a24      a24:	e9 00 00 00 00       	jmp    a29 <.altinstr_replacement+0xa29>	a25: R_X86_64_PC32	.text+0x24c536
0a29      a29:	0f 20 d0             	mov    %cr2,%rax
0a2c      a2c:	0f 20 d8             	mov    %cr3,%rax
0a2f      a2f:	e9 00 00 00 00       	jmp    a34 <.altinstr_replacement+0xa34>	a30: R_X86_64_PC32	.text.unlikely+0x208f8
0a34      a34:	e9 00 00 00 00       	jmp    a39 <.altinstr_replacement+0xa39>	a35: R_X86_64_PC32	.text.unlikely+0x20bf9
0a39      a39:	9c                   	pushf
0a3a      a3a:	58                   	pop    %rax
0a3b      a3b:	fa                   	cli
0a3c      a3c:	9c                   	pushf
0a3d      a3d:	58                   	pop    %rax
0a3e      a3e:	fb                   	sti
0a3f      a3f:	9c                   	pushf
0a40      a40:	58                   	pop    %rax
0a41      a41:	fa                   	cli
0a42      a42:	9c                   	pushf
0a43      a43:	58                   	pop    %rax
0a44      a44:	fb                   	sti
0a45      a45:	e9 00 00 00 00       	jmp    a4a <.altinstr_replacement+0xa4a>	a46: R_X86_64_PC32	.text+0x24d2de
0a4a      a4a:	e9 00 00 00 00       	jmp    a4f <.altinstr_replacement+0xa4f>	a4b: R_X86_64_PC32	.text+0x24d336
0a4f      a4f:	e9 00 00 00 00       	jmp    a54 <.altinstr_replacement+0xa54>	a50: R_X86_64_PC32	.text+0x24d105
0a54      a54:	e9 00 00 00 00       	jmp    a59 <.altinstr_replacement+0xa59>	a55: R_X86_64_PC32	.text+0x24d18a
0a59      a59:	e9 00 00 00 00       	jmp    a5e <.altinstr_replacement+0xa5e>	a5a: R_X86_64_PC32	.text+0x24d1d0
0a5e      a5e:	e9 00 00 00 00       	jmp    a63 <.altinstr_replacement+0xa63>	a5f: R_X86_64_PC32	.text+0x24d5a6
0a63      a63:	e9 00 00 00 00       	jmp    a68 <.altinstr_replacement+0xa68>	a64: R_X86_64_PC32	.text+0x24d580
0a68      a68:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
0a72      a72:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
0a7c      a7c:	48 ba 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rdx
0a86      a86:	0f 01 cb             	stac
0a89      a89:	0f ae e8             	lfence
0a8c      a8c:	0f 01 ca             	clac
0a8f      a8f:	0f 01 ca             	clac
0a92      a92:	48 ba 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rdx
0a9c      a9c:	0f 01 cb             	stac
0a9f      a9f:	0f ae e8             	lfence
0aa2      aa2:	0f 01 ca             	clac
0aa5      aa5:	0f 01 ca             	clac
0aa8      aa8:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
0ab2      ab2:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
0abc      abc:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
0ac6      ac6:	fb                   	sti
0ac7      ac7:	fa                   	cli
0ac8      ac8:	9c                   	pushf
0ac9      ac9:	58                   	pop    %rax
0aca      aca:	e9 00 00 00 00       	jmp    acf <.altinstr_replacement+0xacf>	acb: R_X86_64_PC32	.text+0x25047e
0acf      acf:	e9 00 00 00 00       	jmp    ad4 <.altinstr_replacement+0xad4>	ad0: R_X86_64_PC32	.text+0x2504c3
0ad4      ad4:	9c                   	pushf
0ad5      ad5:	58                   	pop    %rax
0ad6      ad6:	fa                   	cli
0ad7      ad7:	fb                   	sti
0ad8      ad8:	e9 00 00 00 00       	jmp    add <.altinstr_replacement+0xadd>	ad9: R_X86_64_PC32	.text+0x250aae
0add      add:	fb                   	sti
0ade      ade:	9c                   	pushf
0adf      adf:	58                   	pop    %rax
0ae0      ae0:	fa                   	cli
0ae1      ae1:	e9 00 00 00 00       	jmp    ae6 <.altinstr_replacement+0xae6>	ae2: R_X86_64_PC32	.text+0x250b76
0ae6      ae6:	fb                   	sti
0ae7      ae7:	fb                   	sti
0ae8      ae8:	fb                   	sti
0ae9      ae9:	48 ba 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rdx
0af3      af3:	e9 00 00 00 00       	jmp    af8 <.altinstr_replacement+0xaf8>	af4: R_X86_64_PC32	.noinstr.text+0x2a40
0af8      af8:	fb                   	sti
0af9      af9:	9c                   	pushf
0afa      afa:	58                   	pop    %rax
0afb      afb:	fa                   	cli
0afc      afc:	0f 20 d0             	mov    %cr2,%rax
0aff      aff:	e9 00 00 00 00       	jmp    b04 <.altinstr_replacement+0xb04>	b00: R_X86_64_PC32	.noinstr.text+0x3250
0b04      b04:	e9 00 00 00 00       	jmp    b09 <.altinstr_replacement+0xb09>	b05: R_X86_64_PC32	.noinstr.text+0x3504
0b09      b09:	fb                   	sti
0b0a      b0a:	9c                   	pushf
0b0b      b0b:	58                   	pop    %rax
0b0c      b0c:	fa                   	cli
0b0d      b0d:	e9 00 00 00 00       	jmp    b12 <.altinstr_replacement+0xb12>	b0e: R_X86_64_PC32	.init.text+0x3210d
0b12      b12:	9c                   	pushf
0b13      b13:	58                   	pop    %rax
0b14      b14:	fb                   	sti
0b15      b15:	c6 07 00             	movb   $0x0,(%rdi)
0b18      b18:	9c                   	pushf
0b19      b19:	58                   	pop    %rax
0b1a      b1a:	fa                   	cli
0b1b      b1b:	0f 20 d0             	mov    %cr2,%rax
0b1e      b1e:	e9 00 00 00 00       	jmp    b23 <.altinstr_replacement+0xb23>	b1f: R_X86_64_PC32	.noinstr.text+0x4384
0b23      b23:	0f 20 d0             	mov    %cr2,%rax
0b26      b26:	e9 00 00 00 00       	jmp    b2b <.altinstr_replacement+0xb2b>	b27: R_X86_64_PC32	.text+0x25afac
0b2b      b2b:	48 89 f8             	mov    %rdi,%rax
0b2e      b2e:	e9 00 00 00 00       	jmp    b33 <.altinstr_replacement+0xb33>	b2f: R_X86_64_PC32	.text+0x25c164
0b33      b33:	9c                   	pushf
0b34      b34:	58                   	pop    %rax
0b35      b35:	e9 00 00 00 00       	jmp    b3a <.altinstr_replacement+0xb3a>	b36: R_X86_64_PC32	.init.text+0x3309e
0b3a      b3a:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
0b44      b44:	0f 01 cb             	stac
0b47      b47:	0f ae e8             	lfence
0b4a      b4a:	0f 01 ca             	clac
0b4d      b4d:	0f 01 ca             	clac
0b50      b50:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
0b5a      b5a:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
0b64      b64:	e9 00 00 00 00       	jmp    b69 <.altinstr_replacement+0xb69>	b65: R_X86_64_PC32	.text.unlikely+0x21c49
0b69      b69:	48 89 f8             	mov    %rdi,%rax
0b6c      b6c:	48 89 f8             	mov    %rdi,%rax
0b6f      b6f:	48 89 f8             	mov    %rdi,%rax
0b72      b72:	48 89 f8             	mov    %rdi,%rax
0b75      b75:	48 89 f8             	mov    %rdi,%rax
0b78      b78:	48 89 f8             	mov    %rdi,%rax
0b7b      b7b:	e9 00 00 00 00       	jmp    b80 <.altinstr_replacement+0xb80>	b7c: R_X86_64_PC32	.init.text+0x35373
0b80      b80:	48 89 f8             	mov    %rdi,%rax
0b83      b83:	e9 00 00 00 00       	jmp    b88 <.altinstr_replacement+0xb88>	b84: R_X86_64_PC32	.init.text+0x354bb
0b88      b88:	e9 00 00 00 00       	jmp    b8d <.altinstr_replacement+0xb8d>	b89: R_X86_64_PC32	.init.text+0x36917
0b8d      b8d:	e9 00 00 00 00       	jmp    b92 <.altinstr_replacement+0xb92>	b8e: R_X86_64_PC32	.init.text+0x389ee
0b92      b92:	e9 00 00 00 00       	jmp    b97 <.altinstr_replacement+0xb97>	b93: R_X86_64_PC32	.text+0x262a6e
0b97      b97:	e9 00 00 00 00       	jmp    b9c <.altinstr_replacement+0xb9c>	b98: R_X86_64_PC32	.text+0x262c65
0b9c      b9c:	e9 00 00 00 00       	jmp    ba1 <.altinstr_replacement+0xba1>	b9d: R_X86_64_PC32	.text+0x262ae5
0ba1      ba1:	48 89 f8             	mov    %rdi,%rax
0ba4      ba4:	9c                   	pushf
0ba5      ba5:	58                   	pop    %rax
0ba6      ba6:	fa                   	cli
0ba7      ba7:	9c                   	pushf
0ba8      ba8:	58                   	pop    %rax
0ba9      ba9:	fb                   	sti
0baa      baa:	e9 00 00 00 00       	jmp    baf <.altinstr_replacement+0xbaf>	bab: R_X86_64_PC32	.text+0x263514
0baf      baf:	9c                   	pushf
0bb0      bb0:	58                   	pop    %rax
0bb1      bb1:	fa                   	cli
0bb2      bb2:	9c                   	pushf
0bb3      bb3:	58                   	pop    %rax
0bb4      bb4:	fb                   	sti
0bb5      bb5:	9c                   	pushf
0bb6      bb6:	58                   	pop    %rax
0bb7      bb7:	fa                   	cli
0bb8      bb8:	9c                   	pushf
0bb9      bb9:	58                   	pop    %rax
0bba      bba:	fb                   	sti
0bbb      bbb:	e9 00 00 00 00       	jmp    bc0 <.altinstr_replacement+0xbc0>	bbc: R_X86_64_PC32	.text+0x263f75
0bc0      bc0:	e9 00 00 00 00       	jmp    bc5 <.altinstr_replacement+0xbc5>	bc1: R_X86_64_PC32	.text+0x264732
0bc5      bc5:	48 ba 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rdx
0bcf      bcf:	48 ba 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rdx
0bd9      bd9:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
0be3      be3:	0f ae e8             	lfence
0be6      be6:	0f 31                	rdtsc
0be8      be8:	0f 01 f9             	rdtscp
0beb      beb:	9c                   	pushf
0bec      bec:	58                   	pop    %rax
0bed      bed:	fa                   	cli
0bee      bee:	9c                   	pushf
0bef      bef:	58                   	pop    %rax
0bf0      bf0:	fb                   	sti
0bf1      bf1:	9c                   	pushf
0bf2      bf2:	58                   	pop    %rax
0bf3      bf3:	fa                   	cli
0bf4      bf4:	9c                   	pushf
0bf5      bf5:	58                   	pop    %rax
0bf6      bf6:	fb                   	sti
0bf7      bf7:	9c                   	pushf
0bf8      bf8:	58                   	pop    %rax
0bf9      bf9:	fa                   	cli
0bfa      bfa:	9c                   	pushf
0bfb      bfb:	58                   	pop    %rax
0bfc      bfc:	fb                   	sti
0bfd      bfd:	9c                   	pushf
0bfe      bfe:	58                   	pop    %rax
0bff      bff:	fa                   	cli
0c00      c00:	9c                   	pushf
0c01      c01:	58                   	pop    %rax
0c02      c02:	fb                   	sti
0c03      c03:	e9 00 00 00 00       	jmp    c08 <.altinstr_replacement+0xc08>	c04: R_X86_64_PC32	.ref.text+0x14bb
0c08      c08:	9c                   	pushf
0c09      c09:	58                   	pop    %rax
0c0a      c0a:	fa                   	cli
0c0b      c0b:	9c                   	pushf
0c0c      c0c:	58                   	pop    %rax
0c0d      c0d:	fb                   	sti
0c0e      c0e:	9c                   	pushf
0c0f      c0f:	58                   	pop    %rax
0c10      c10:	fa                   	cli
0c11      c11:	9c                   	pushf
0c12      c12:	58                   	pop    %rax
0c13      c13:	fb                   	sti
0c14      c14:	9c                   	pushf
0c15      c15:	58                   	pop    %rax
0c16      c16:	fb                   	sti
0c17      c17:	fa                   	cli
0c18      c18:	fb                   	sti
0c19      c19:	e9 00 00 00 00       	jmp    c1e <.altinstr_replacement+0xc1e>	c1a: R_X86_64_PC32	.text+0x26a334
0c1e      c1e:	e9 00 00 00 00       	jmp    c23 <.altinstr_replacement+0xc23>	c1f: R_X86_64_PC32	.text+0x26a60d
0c23      c23:	9c                   	pushf
0c24      c24:	58                   	pop    %rax
0c25      c25:	fa                   	cli
0c26      c26:	e9 00 00 00 00       	jmp    c2b <.altinstr_replacement+0xc2b>	c27: R_X86_64_PC32	.text+0x26adf3
0c2b      c2b:	9c                   	pushf
0c2c      c2c:	58                   	pop    %rax
0c2d      c2d:	fb                   	sti
0c2e      c2e:	e9 00 00 00 00       	jmp    c33 <.altinstr_replacement+0xc33>	c2f: R_X86_64_PC32	.text+0x26aea2
0c33      c33:	e9 00 00 00 00       	jmp    c38 <.altinstr_replacement+0xc38>	c34: R_X86_64_PC32	.text+0x26aebf
0c38      c38:	e9 00 00 00 00       	jmp    c3d <.altinstr_replacement+0xc3d>	c39: R_X86_64_PC32	.text+0x26af11
0c3d      c3d:	e9 00 00 00 00       	jmp    c42 <.altinstr_replacement+0xc42>	c3e: R_X86_64_PC32	.text+0x26ae69
0c42      c42:	e9 00 00 00 00       	jmp    c47 <.altinstr_replacement+0xc47>	c43: R_X86_64_PC32	.text+0x26b438
0c47      c47:	e9 00 00 00 00       	jmp    c4c <.altinstr_replacement+0xc4c>	c48: R_X86_64_PC32	.text+0x26b649
0c4c      c4c:	e9 00 00 00 00       	jmp    c51 <.altinstr_replacement+0xc51>	c4d: R_X86_64_PC32	.text+0x26b851
0c51      c51:	e9 00 00 00 00       	jmp    c56 <.altinstr_replacement+0xc56>	c52: R_X86_64_PC32	.text+0x26b6a5
0c56      c56:	e9 00 00 00 00       	jmp    c5b <.altinstr_replacement+0xc5b>	c57: R_X86_64_PC32	.text+0x26b3ff
0c5b      c5b:	e9 00 00 00 00       	jmp    c60 <.altinstr_replacement+0xc60>	c5c: R_X86_64_PC32	.text+0x26b748
0c60      c60:	e9 00 00 00 00       	jmp    c65 <.altinstr_replacement+0xc65>	c61: R_X86_64_PC32	.text+0x26b8ab
0c65      c65:	e9 00 00 00 00       	jmp    c6a <.altinstr_replacement+0xc6a>	c66: R_X86_64_PC32	.text+0x26b937
0c6a      c6a:	e9 00 00 00 00       	jmp    c6f <.altinstr_replacement+0xc6f>	c6b: R_X86_64_PC32	.text+0x26b988
0c6f      c6f:	e9 00 00 00 00       	jmp    c74 <.altinstr_replacement+0xc74>	c70: R_X86_64_PC32	.text+0x26b992
0c74      c74:	9c                   	pushf
0c75      c75:	58                   	pop    %rax
0c76      c76:	fa                   	cli
0c77      c77:	e9 00 00 00 00       	jmp    c7c <.altinstr_replacement+0xc7c>	c78: R_X86_64_PC32	.text+0x26c033
0c7c      c7c:	9c                   	pushf
0c7d      c7d:	58                   	pop    %rax
0c7e      c7e:	fa                   	cli
0c7f      c7f:	fb                   	sti
0c80      c80:	9c                   	pushf
0c81      c81:	58                   	pop    %rax
0c82      c82:	fa                   	cli
0c83      c83:	9c                   	pushf
0c84      c84:	58                   	pop    %rax
0c85      c85:	fb                   	sti
0c86      c86:	48 0f ae 37          	xsaveopt64 (%rdi)
0c8a      c8a:	48 0f c7 27          	xsavec64 (%rdi)
0c8e      c8e:	48 0f c7 2f          	xsaves64 (%rdi)
0c92      c92:	e9 00 00 00 00       	jmp    c97 <.altinstr_replacement+0xc97>	c93: R_X86_64_PC32	.text+0x26d237
0c97      c97:	e9 00 00 00 00       	jmp    c9c <.altinstr_replacement+0xc9c>	c98: R_X86_64_PC32	.text+0x26d5a4
0c9c      c9c:	e9 00 00 00 00       	jmp    ca1 <.altinstr_replacement+0xca1>	c9d: R_X86_64_PC32	.text+0x26d6d1
0ca1      ca1:	e9 00 00 00 00       	jmp    ca6 <.altinstr_replacement+0xca6>	ca2: R_X86_64_PC32	.text+0x26e2ce
0ca6      ca6:	e9 00 00 00 00       	jmp    cab <.altinstr_replacement+0xcab>	ca7: R_X86_64_PC32	.text+0x26e5b9
0cab      cab:	e9 00 00 00 00       	jmp    cb0 <.altinstr_replacement+0xcb0>	cac: R_X86_64_PC32	.text+0x26e602
0cb0      cb0:	48 0f c7 1f          	xrstors64 (%rdi)
0cb4      cb4:	e9 00 00 00 00       	jmp    cb9 <.altinstr_replacement+0xcb9>	cb5: R_X86_64_PC32	.text+0x26f0c3
0cb9      cb9:	e9 00 00 00 00       	jmp    cbe <.altinstr_replacement+0xcbe>	cba: R_X86_64_PC32	.text+0x26f446
0cbe      cbe:	e9 00 00 00 00       	jmp    cc3 <.altinstr_replacement+0xcc3>	cbf: R_X86_64_PC32	.text+0x26f53e
0cc3      cc3:	e9 00 00 00 00       	jmp    cc8 <.altinstr_replacement+0xcc8>	cc4: R_X86_64_PC32	.text+0x270261
0cc8      cc8:	e9 00 00 00 00       	jmp    ccd <.altinstr_replacement+0xccd>	cc9: R_X86_64_PC32	.text+0x270926
0ccd      ccd:	48 0f c7 1f          	xrstors64 (%rdi)
0cd1      cd1:	e9 00 00 00 00       	jmp    cd6 <.altinstr_replacement+0xcd6>	cd2: R_X86_64_PC32	.text+0x270902
0cd6      cd6:	48 0f c7 1f          	xrstors64 (%rdi)
0cda      cda:	e9 00 00 00 00       	jmp    cdf <.altinstr_replacement+0xcdf>	cdb: R_X86_64_PC32	.text+0x270b37
0cdf      cdf:	e8 00 00 00 00       	call   ce4 <.altinstr_replacement+0xce4>	ce0: R_X86_64_PLT32	copy_user_generic_string-0x4
0ce4      ce4:	e8 00 00 00 00       	call   ce9 <.altinstr_replacement+0xce9>	ce5: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
0ce9      ce9:	e9 00 00 00 00       	jmp    cee <.altinstr_replacement+0xcee>	cea: R_X86_64_PC32	.text+0x271490
0cee      cee:	e9 00 00 00 00       	jmp    cf3 <.altinstr_replacement+0xcf3>	cef: R_X86_64_PC32	.text+0x271782
0cf3      cf3:	e9 00 00 00 00       	jmp    cf8 <.altinstr_replacement+0xcf8>	cf4: R_X86_64_PC32	.text+0x2718bc
0cf8      cf8:	e9 00 00 00 00       	jmp    cfd <.altinstr_replacement+0xcfd>	cf9: R_X86_64_PC32	.text+0x2719d7
0cfd      cfd:	e9 00 00 00 00       	jmp    d02 <.altinstr_replacement+0xd02>	cfe: R_X86_64_PC32	.text+0x271e39
0d02      d02:	e9 00 00 00 00       	jmp    d07 <.altinstr_replacement+0xd07>	d03: R_X86_64_PC32	.text+0x27204d
0d07      d07:	e8 00 00 00 00       	call   d0c <.altinstr_replacement+0xd0c>	d08: R_X86_64_PLT32	copy_user_generic_string-0x4
0d0c      d0c:	e8 00 00 00 00       	call   d11 <.altinstr_replacement+0xd11>	d0d: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
0d11      d11:	48 0f ae 37          	xsaveopt64 (%rdi)
0d15      d15:	48 0f c7 27          	xsavec64 (%rdi)
0d19      d19:	48 0f c7 2f          	xsaves64 (%rdi)
0d1d      d1d:	e8 00 00 00 00       	call   d22 <.altinstr_replacement+0xd22>	d1e: R_X86_64_PLT32	copy_user_generic_string-0x4
0d22      d22:	e8 00 00 00 00       	call   d27 <.altinstr_replacement+0xd27>	d23: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
0d27      d27:	e9 00 00 00 00       	jmp    d2c <.altinstr_replacement+0xd2c>	d28: R_X86_64_PC32	.text+0x2723c9
0d2c      d2c:	e8 00 00 00 00       	call   d31 <.altinstr_replacement+0xd31>	d2d: R_X86_64_PLT32	copy_user_generic_string-0x4
0d31      d31:	e8 00 00 00 00       	call   d36 <.altinstr_replacement+0xd36>	d32: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
0d36      d36:	e9 00 00 00 00       	jmp    d3b <.altinstr_replacement+0xd3b>	d37: R_X86_64_PC32	.text+0x27285c
0d3b      d3b:	0f 01 cb             	stac
0d3e      d3e:	0f 01 ca             	clac
0d41      d41:	0f 01 cb             	stac
0d44      d44:	0f 01 ca             	clac
0d47      d47:	48 0f c7 1f          	xrstors64 (%rdi)
0d4b      d4b:	0f 01 cb             	stac
0d4e      d4e:	0f 01 ca             	clac
0d51      d51:	48 0f c7 1f          	xrstors64 (%rdi)
0d55      d55:	e9 00 00 00 00       	jmp    d5a <.altinstr_replacement+0xd5a>	d56: R_X86_64_PC32	.text+0x272cb5
0d5a      d5a:	e8 00 00 00 00       	call   d5f <.altinstr_replacement+0xd5f>	d5b: R_X86_64_PLT32	copy_user_generic_string-0x4
0d5f      d5f:	e8 00 00 00 00       	call   d64 <.altinstr_replacement+0xd64>	d60: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
0d64      d64:	e8 00 00 00 00       	call   d69 <.altinstr_replacement+0xd69>	d65: R_X86_64_PLT32	copy_user_generic_string-0x4
0d69      d69:	e8 00 00 00 00       	call   d6e <.altinstr_replacement+0xd6e>	d6a: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
0d6e      d6e:	e9 00 00 00 00       	jmp    d73 <.altinstr_replacement+0xd73>	d6f: R_X86_64_PC32	.text+0x2731ac
0d73      d73:	e8 00 00 00 00       	call   d78 <.altinstr_replacement+0xd78>	d74: R_X86_64_PLT32	copy_user_generic_string-0x4
0d78      d78:	e8 00 00 00 00       	call   d7d <.altinstr_replacement+0xd7d>	d79: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
0d7d      d7d:	e9 00 00 00 00       	jmp    d82 <.altinstr_replacement+0xd82>	d7e: R_X86_64_PC32	.text+0x27328d
0d82      d82:	e9 00 00 00 00       	jmp    d87 <.altinstr_replacement+0xd87>	d83: R_X86_64_PC32	.text+0x27342d
0d87      d87:	e9 00 00 00 00       	jmp    d8c <.altinstr_replacement+0xd8c>	d88: R_X86_64_PC32	.text+0x27353d
0d8c      d8c:	49 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r13
0d96      d96:	e9 00 00 00 00       	jmp    d9b <.altinstr_replacement+0xd9b>	d97: R_X86_64_PC32	.text+0x2736a1
0d9b      d9b:	e9 00 00 00 00       	jmp    da0 <.altinstr_replacement+0xda0>	d9c: R_X86_64_PC32	.text+0x273939
0da0      da0:	0f 01 cb             	stac
0da3      da3:	0f 01 ca             	clac
0da6      da6:	0f 01 cb             	stac
0da9      da9:	0f 01 ca             	clac
0dac      dac:	e9 00 00 00 00       	jmp    db1 <.altinstr_replacement+0xdb1>	dad: R_X86_64_PC32	.text+0x273ca4
0db1      db1:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
0dbb      dbb:	e9 00 00 00 00       	jmp    dc0 <.altinstr_replacement+0xdc0>	dbc: R_X86_64_PC32	.text+0x273e53
0dc0      dc0:	e9 00 00 00 00       	jmp    dc5 <.altinstr_replacement+0xdc5>	dc1: R_X86_64_PC32	.init.text+0x3cce9
0dc5      dc5:	e9 00 00 00 00       	jmp    dca <.altinstr_replacement+0xdca>	dc6: R_X86_64_PC32	.text+0x273eeb
0dca      dca:	e9 00 00 00 00       	jmp    dcf <.altinstr_replacement+0xdcf>	dcb: R_X86_64_PC32	.text+0x273f1d
0dcf      dcf:	9c                   	pushf
0dd0      dd0:	58                   	pop    %rax
0dd1      dd1:	fa                   	cli
0dd2      dd2:	9c                   	pushf
0dd3      dd3:	58                   	pop    %rax
0dd4      dd4:	fb                   	sti
0dd5      dd5:	9c                   	pushf
0dd6      dd6:	58                   	pop    %rax
0dd7      dd7:	fa                   	cli
0dd8      dd8:	9c                   	pushf
0dd9      dd9:	58                   	pop    %rax
0dda      dda:	fb                   	sti
0ddb      ddb:	e9 00 00 00 00       	jmp    de0 <.altinstr_replacement+0xde0>	ddc: R_X86_64_PC32	.text+0x2749c3
0de0      de0:	e9 00 00 00 00       	jmp    de5 <.altinstr_replacement+0xde5>	de1: R_X86_64_PC32	.text+0x274bf7
0de5      de5:	e9 00 00 00 00       	jmp    dea <.altinstr_replacement+0xdea>	de6: R_X86_64_PC32	.text+0x2752d7
0dea      dea:	e9 00 00 00 00       	jmp    def <.altinstr_replacement+0xdef>	deb: R_X86_64_PC32	.text+0x275640
0def      def:	e9 00 00 00 00       	jmp    df4 <.altinstr_replacement+0xdf4>	df0: R_X86_64_PC32	.text+0x2755ef
0df4      df4:	e9 00 00 00 00       	jmp    df9 <.altinstr_replacement+0xdf9>	df5: R_X86_64_PC32	.text+0x275814
0df9      df9:	e9 00 00 00 00       	jmp    dfe <.altinstr_replacement+0xdfe>	dfa: R_X86_64_PC32	.text+0x275b7e
0dfe      dfe:	e9 00 00 00 00       	jmp    e03 <.altinstr_replacement+0xe03>	dff: R_X86_64_PC32	.text+0x275bf8
0e03      e03:	e9 00 00 00 00       	jmp    e08 <.altinstr_replacement+0xe08>	e04: R_X86_64_PC32	.init.text+0x3e73f
0e08      e08:	e9 00 00 00 00       	jmp    e0d <.altinstr_replacement+0xe0d>	e09: R_X86_64_PC32	.init.text+0x3e776
0e0d      e0d:	e9 00 00 00 00       	jmp    e12 <.altinstr_replacement+0xe12>	e0e: R_X86_64_PC32	.init.text+0x3ef55
0e12      e12:	e9 00 00 00 00       	jmp    e17 <.altinstr_replacement+0xe17>	e13: R_X86_64_PC32	.init.text+0x3efb1
0e17      e17:	e9 00 00 00 00       	jmp    e1c <.altinstr_replacement+0xe1c>	e18: R_X86_64_PC32	.init.text+0x3f083
0e1c      e1c:	e9 00 00 00 00       	jmp    e21 <.altinstr_replacement+0xe21>	e1d: R_X86_64_PC32	.init.text+0x3f0a0
0e21      e21:	e9 00 00 00 00       	jmp    e26 <.altinstr_replacement+0xe26>	e22: R_X86_64_PC32	.init.text+0x3f111
0e26      e26:	e9 00 00 00 00       	jmp    e2b <.altinstr_replacement+0xe2b>	e27: R_X86_64_PC32	.init.text+0x3f4e3
0e2b      e2b:	e9 00 00 00 00       	jmp    e30 <.altinstr_replacement+0xe30>	e2c: R_X86_64_PC32	.text+0x275e34
0e30      e30:	e9 00 00 00 00       	jmp    e35 <.altinstr_replacement+0xe35>	e31: R_X86_64_PC32	.text+0x275e99
0e35      e35:	e9 00 00 00 00       	jmp    e3a <.altinstr_replacement+0xe3a>	e36: R_X86_64_PC32	.text+0x275e69
0e3a      e3a:	e9 00 00 00 00       	jmp    e3f <.altinstr_replacement+0xe3f>	e3b: R_X86_64_PC32	.text+0x27612f
0e3f      e3f:	e9 00 00 00 00       	jmp    e44 <.altinstr_replacement+0xe44>	e40: R_X86_64_PC32	.text+0x276152
0e44      e44:	e9 00 00 00 00       	jmp    e49 <.altinstr_replacement+0xe49>	e45: R_X86_64_PC32	.text+0x2761e4
0e49      e49:	e9 00 00 00 00       	jmp    e4e <.altinstr_replacement+0xe4e>	e4a: R_X86_64_PC32	.text+0x276243
0e4e      e4e:	e9 00 00 00 00       	jmp    e53 <.altinstr_replacement+0xe53>	e4f: R_X86_64_PC32	.text+0x2776ad
0e53      e53:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
0e5d      e5d:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
0e67      e67:	48 ba 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rdx
0e71      e71:	48 ba 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rdx
0e7b      e7b:	48 ba 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rdx
0e85      e85:	48 ba 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rdx
0e8f      e8f:	48 ba 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rdx
0e99      e99:	48 ba 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rdx
0ea3      ea3:	48 ba 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rdx
0ead      ead:	e8 00 00 00 00       	call   eb2 <.altinstr_replacement+0xeb2>	eae: R_X86_64_PLT32	copy_user_generic_string-0x4
0eb2      eb2:	e8 00 00 00 00       	call   eb7 <.altinstr_replacement+0xeb7>	eb3: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
0eb7      eb7:	9c                   	pushf
0eb8      eb8:	58                   	pop    %rax
0eb9      eb9:	fa                   	cli
0eba      eba:	fb                   	sti
0ebb      ebb:	e9 00 00 00 00       	jmp    ec0 <.altinstr_replacement+0xec0>	ebc: R_X86_64_PC32	.text.unlikely+0x2325b
0ec0      ec0:	48 89 f8             	mov    %rdi,%rax
0ec3      ec3:	e9 00 00 00 00       	jmp    ec8 <.altinstr_replacement+0xec8>	ec4: R_X86_64_PC32	.text.unlikely+0x23364
0ec8      ec8:	48 89 f8             	mov    %rdi,%rax
0ecb      ecb:	48 89 f8             	mov    %rdi,%rax
0ece      ece:	48 89 f8             	mov    %rdi,%rax
0ed1      ed1:	48 89 f8             	mov    %rdi,%rax
0ed4      ed4:	0f 22 df             	mov    %rdi,%cr3
0ed7      ed7:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
0ee1      ee1:	48 ba 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rdx
0eeb      eeb:	9c                   	pushf
0eec      eec:	58                   	pop    %rax
0eed      eed:	fa                   	cli
0eee      eee:	9c                   	pushf
0eef      eef:	58                   	pop    %rax
0ef0      ef0:	fb                   	sti
0ef1      ef1:	9c                   	pushf
0ef2      ef2:	58                   	pop    %rax
0ef3      ef3:	fa                   	cli
0ef4      ef4:	9c                   	pushf
0ef5      ef5:	58                   	pop    %rax
0ef6      ef6:	fb                   	sti
0ef7      ef7:	e9 00 00 00 00       	jmp    efc <.altinstr_replacement+0xefc>	ef8: R_X86_64_PC32	.text+0x282d7f
0efc      efc:	e9 00 00 00 00       	jmp    f01 <.altinstr_replacement+0xf01>	efd: R_X86_64_PC32	.text+0x282e27
0f01      f01:	e9 00 00 00 00       	jmp    f06 <.altinstr_replacement+0xf06>	f02: R_X86_64_PC32	.text+0x282ea7
0f06      f06:	e9 00 00 00 00       	jmp    f0b <.altinstr_replacement+0xf0b>	f07: R_X86_64_PC32	.text+0x2845c7
0f0b      f0b:	e9 00 00 00 00       	jmp    f10 <.altinstr_replacement+0xf10>	f0c: R_X86_64_PC32	.text+0x284652
0f10      f10:	e9 00 00 00 00       	jmp    f15 <.altinstr_replacement+0xf15>	f11: R_X86_64_PC32	.text+0x284652
0f15      f15:	e9 00 00 00 00       	jmp    f1a <.altinstr_replacement+0xf1a>	f16: R_X86_64_PC32	.text+0x28469a
0f1a      f1a:	e9 00 00 00 00       	jmp    f1f <.altinstr_replacement+0xf1f>	f1b: R_X86_64_PC32	.text+0x284652
0f1f      f1f:	e9 00 00 00 00       	jmp    f24 <.altinstr_replacement+0xf24>	f20: R_X86_64_PC32	.init.text+0x416f3
0f24      f24:	e9 00 00 00 00       	jmp    f29 <.altinstr_replacement+0xf29>	f25: R_X86_64_PC32	.text+0x28655c
0f29      f29:	e9 00 00 00 00       	jmp    f2e <.altinstr_replacement+0xf2e>	f2a: R_X86_64_PC32	.text+0x286577
0f2e      f2e:	e9 00 00 00 00       	jmp    f33 <.altinstr_replacement+0xf33>	f2f: R_X86_64_PC32	.text+0x286583
0f33      f33:	e9 00 00 00 00       	jmp    f38 <.altinstr_replacement+0xf38>	f34: R_X86_64_PC32	.text+0x2865dc
0f38      f38:	e9 00 00 00 00       	jmp    f3d <.altinstr_replacement+0xf3d>	f39: R_X86_64_PC32	.text+0x287cdd
0f3d      f3d:	e9 00 00 00 00       	jmp    f42 <.altinstr_replacement+0xf42>	f3e: R_X86_64_PC32	.init.text+0x4628a
0f42      f42:	e9 00 00 00 00       	jmp    f47 <.altinstr_replacement+0xf47>	f43: R_X86_64_PC32	.init.text+0x462a7
0f47      f47:	e9 00 00 00 00       	jmp    f4c <.altinstr_replacement+0xf4c>	f48: R_X86_64_PC32	.init.text+0x4744e
0f4c      f4c:	e9 00 00 00 00       	jmp    f51 <.altinstr_replacement+0xf51>	f4d: R_X86_64_PC32	.text+0x2898c9
0f51      f51:	e9 00 00 00 00       	jmp    f56 <.altinstr_replacement+0xf56>	f52: R_X86_64_PC32	.text+0x289aa9
0f56      f56:	e9 00 00 00 00       	jmp    f5b <.altinstr_replacement+0xf5b>	f57: R_X86_64_PC32	.text+0x289bb4
0f5b      f5b:	9c                   	pushf
0f5c      f5c:	58                   	pop    %rax
0f5d      f5d:	fa                   	cli
0f5e      f5e:	fb                   	sti
0f5f      f5f:	e9 00 00 00 00       	jmp    f64 <.altinstr_replacement+0xf64>	f60: R_X86_64_PC32	.text+0x28f2d5
0f64      f64:	e9 00 00 00 00       	jmp    f69 <.altinstr_replacement+0xf69>	f65: R_X86_64_PC32	.text+0x28f631
0f69      f69:	e9 00 00 00 00       	jmp    f6e <.altinstr_replacement+0xf6e>	f6a: R_X86_64_PC32	.text+0x295b53
0f6e      f6e:	e9 00 00 00 00       	jmp    f73 <.altinstr_replacement+0xf73>	f6f: R_X86_64_PC32	.text+0x29605f
0f73      f73:	e9 00 00 00 00       	jmp    f78 <.altinstr_replacement+0xf78>	f74: R_X86_64_PC32	.text+0x296127
0f78      f78:	e9 00 00 00 00       	jmp    f7d <.altinstr_replacement+0xf7d>	f79: R_X86_64_PC32	.text+0x296139
0f7d      f7d:	fb                   	sti
0f7e      f7e:	9c                   	pushf
0f7f      f7f:	58                   	pop    %rax
0f80      f80:	fa                   	cli
0f81      f81:	9c                   	pushf
0f82      f82:	58                   	pop    %rax
0f83      f83:	fb                   	sti
0f84      f84:	9c                   	pushf
0f85      f85:	58                   	pop    %rax
0f86      f86:	fa                   	cli
0f87      f87:	9c                   	pushf
0f88      f88:	58                   	pop    %rax
0f89      f89:	fb                   	sti
0f8a      f8a:	e9 00 00 00 00       	jmp    f8f <.altinstr_replacement+0xf8f>	f8b: R_X86_64_PC32	.text+0x299d60
0f8f      f8f:	e9 00 00 00 00       	jmp    f94 <.altinstr_replacement+0xf94>	f90: R_X86_64_PC32	.text+0x299d72
0f94      f94:	e9 00 00 00 00       	jmp    f99 <.altinstr_replacement+0xf99>	f95: R_X86_64_PC32	.text+0x29a282
0f99      f99:	e9 00 00 00 00       	jmp    f9e <.altinstr_replacement+0xf9e>	f9a: R_X86_64_PC32	.text+0x29a692
0f9e      f9e:	e9 00 00 00 00       	jmp    fa3 <.altinstr_replacement+0xfa3>	f9f: R_X86_64_PC32	.noinstr.text+0x5509
0fa3      fa3:	e9 00 00 00 00       	jmp    fa8 <.altinstr_replacement+0xfa8>	fa4: R_X86_64_PC32	.noinstr.text+0x541c
0fa8      fa8:	e9 00 00 00 00       	jmp    fad <.altinstr_replacement+0xfad>	fa9: R_X86_64_PC32	.text+0x29b4a4
0fad      fad:	e9 00 00 00 00       	jmp    fb2 <.altinstr_replacement+0xfb2>	fae: R_X86_64_PC32	.text+0x29b4b1
0fb2      fb2:	e9 00 00 00 00       	jmp    fb7 <.altinstr_replacement+0xfb7>	fb3: R_X86_64_PC32	.text+0x29b4be
0fb7      fb7:	e9 00 00 00 00       	jmp    fbc <.altinstr_replacement+0xfbc>	fb8: R_X86_64_PC32	.noinstr.text+0x607f
0fbc      fbc:	e9 00 00 00 00       	jmp    fc1 <.altinstr_replacement+0xfc1>	fbd: R_X86_64_PC32	.noinstr.text+0x60e0
0fc1      fc1:	e9 00 00 00 00       	jmp    fc6 <.altinstr_replacement+0xfc6>	fc2: R_X86_64_PC32	.noinstr.text+0x60f2
0fc6      fc6:	e9 00 00 00 00       	jmp    fcb <.altinstr_replacement+0xfcb>	fc7: R_X86_64_PC32	.init.text+0x492eb
0fcb      fcb:	e9 00 00 00 00       	jmp    fd0 <.altinstr_replacement+0xfd0>	fcc: R_X86_64_PC32	.noinstr.text+0x64c1
0fd0      fd0:	e9 00 00 00 00       	jmp    fd5 <.altinstr_replacement+0xfd5>	fd1: R_X86_64_PC32	.noinstr.text+0x6683
0fd5      fd5:	e9 00 00 00 00       	jmp    fda <.altinstr_replacement+0xfda>	fd6: R_X86_64_PC32	.text+0x29c108
0fda      fda:	9c                   	pushf
0fdb      fdb:	58                   	pop    %rax
0fdc      fdc:	fa                   	cli
0fdd      fdd:	9c                   	pushf
0fde      fde:	58                   	pop    %rax
0fdf      fdf:	fb                   	sti
0fe0      fe0:	e9 00 00 00 00       	jmp    fe5 <.altinstr_replacement+0xfe5>	fe1: R_X86_64_PC32	.text+0x29fbe3
0fe5      fe5:	e9 00 00 00 00       	jmp    fea <.altinstr_replacement+0xfea>	fe6: R_X86_64_PC32	.text+0x2a14c6
0fea      fea:	e9 00 00 00 00       	jmp    fef <.altinstr_replacement+0xfef>	feb: R_X86_64_PC32	.text+0x2a14b5
0fef      fef:	e9 00 00 00 00       	jmp    ff4 <.altinstr_replacement+0xff4>	ff0: R_X86_64_PC32	.text+0x2a210d
0ff4      ff4:	e9 00 00 00 00       	jmp    ff9 <.altinstr_replacement+0xff9>	ff5: R_X86_64_PC32	.text+0x2a26bd
0ff9      ff9:	e9 00 00 00 00       	jmp    ffe <.altinstr_replacement+0xffe>	ffa: R_X86_64_PC32	.text+0x2a26cf
0ffe      ffe:	e9 00 00 00 00       	jmp    1003 <.altinstr_replacement+0x1003>	fff: R_X86_64_PC32	.text+0x2a44c6
1003     1003:	9c                   	pushf
1004     1004:	58                   	pop    %rax
1005     1005:	fa                   	cli
1006     1006:	9c                   	pushf
1007     1007:	58                   	pop    %rax
1008     1008:	fb                   	sti
1009     1009:	9c                   	pushf
100a     100a:	58                   	pop    %rax
100b     100b:	fa                   	cli
100c     100c:	9c                   	pushf
100d     100d:	58                   	pop    %rax
100e     100e:	fb                   	sti
100f     100f:	e9 00 00 00 00       	jmp    1014 <.altinstr_replacement+0x1014>	1010: R_X86_64_PC32	.text.unlikely+0x254df
1014     1014:	e9 00 00 00 00       	jmp    1019 <.altinstr_replacement+0x1019>	1015: R_X86_64_PC32	.text.unlikely+0x253e3
1019     1019:	e9 00 00 00 00       	jmp    101e <.altinstr_replacement+0x101e>	101a: R_X86_64_PC32	.text.unlikely+0x25437
101e     101e:	0f ae e8             	lfence
1021     1021:	0f 31                	rdtsc
1023     1023:	0f 01 f9             	rdtscp
1026     1026:	e9 00 00 00 00       	jmp    102b <.altinstr_replacement+0x102b>	1027: R_X86_64_PC32	.text+0x2a5e7a
102b     102b:	e9 00 00 00 00       	jmp    1030 <.altinstr_replacement+0x1030>	102c: R_X86_64_PC32	.text+0x2acf8a
1030     1030:	e9 00 00 00 00       	jmp    1035 <.altinstr_replacement+0x1035>	1031: R_X86_64_PC32	.text+0x2acfb9
1035     1035:	0f 09                	wbinvd
1037     1037:	0f 09                	wbinvd
1039     1039:	9c                   	pushf
103a     103a:	58                   	pop    %rax
103b     103b:	fa                   	cli
103c     103c:	9c                   	pushf
103d     103d:	58                   	pop    %rax
103e     103e:	fb                   	sti
103f     103f:	9c                   	pushf
1040     1040:	58                   	pop    %rax
1041     1041:	fa                   	cli
1042     1042:	9c                   	pushf
1043     1043:	58                   	pop    %rax
1044     1044:	fb                   	sti
1045     1045:	9c                   	pushf
1046     1046:	58                   	pop    %rax
1047     1047:	fa                   	cli
1048     1048:	9c                   	pushf
1049     1049:	58                   	pop    %rax
104a     104a:	fb                   	sti
104b     104b:	9c                   	pushf
104c     104c:	58                   	pop    %rax
104d     104d:	fa                   	cli
104e     104e:	fb                   	sti
104f     104f:	9c                   	pushf
1050     1050:	58                   	pop    %rax
1051     1051:	fa                   	cli
1052     1052:	0f ae e8             	lfence
1055     1055:	0f 31                	rdtsc
1057     1057:	0f 01 f9             	rdtscp
105a     105a:	0f ae e8             	lfence
105d     105d:	0f 31                	rdtsc
105f     105f:	0f 01 f9             	rdtscp
1062     1062:	0f ae e8             	lfence
1065     1065:	0f 31                	rdtsc
1067     1067:	0f 01 f9             	rdtscp
106a     106a:	fb                   	sti
106b     106b:	9c                   	pushf
106c     106c:	58                   	pop    %rax
106d     106d:	fa                   	cli
106e     106e:	fb                   	sti
106f     106f:	fb                   	sti
1070     1070:	e9 00 00 00 00       	jmp    1075 <.altinstr_replacement+0x1075>	1071: R_X86_64_PC32	.init.text+0x539a6
1075     1075:	e9 00 00 00 00       	jmp    107a <.altinstr_replacement+0x107a>	1076: R_X86_64_PC32	.init.text+0x53aea
107a     107a:	e9 00 00 00 00       	jmp    107f <.altinstr_replacement+0x107f>	107b: R_X86_64_PC32	.text+0x2cecc5
107f     107f:	e9 00 00 00 00       	jmp    1084 <.altinstr_replacement+0x1084>	1080: R_X86_64_PC32	.text+0x2cf5a1
1084     1084:	e9 00 00 00 00       	jmp    1089 <.altinstr_replacement+0x1089>	1085: R_X86_64_PC32	.init.text+0x54508
1089     1089:	9c                   	pushf
108a     108a:	58                   	pop    %rax
108b     108b:	49 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r13
1095     1095:	0f 01 cb             	stac
1098     1098:	0f 01 ca             	clac
109b     109b:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
10a5     10a5:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
10af     10af:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
10b9     10b9:	0f 01 cb             	stac
10bc     10bc:	0f 01 ca             	clac
10bf     10bf:	e9 00 00 00 00       	jmp    10c4 <.altinstr_replacement+0x10c4>	10c0: R_X86_64_PC32	.text+0x2d683f
10c4     10c4:	e9 00 00 00 00       	jmp    10c9 <.altinstr_replacement+0x10c9>	10c5: R_X86_64_PC32	.init.text+0x54857
10c9     10c9:	0f 01 c1             	vmcall
10cc     10cc:	0f 01 d9             	vmmcall
10cf     10cf:	9c                   	pushf
10d0     10d0:	58                   	pop    %rax
10d1     10d1:	fa                   	cli
10d2     10d2:	fb                   	sti
10d3     10d3:	9c                   	pushf
10d4     10d4:	58                   	pop    %rax
10d5     10d5:	fa                   	cli
10d6     10d6:	fb                   	sti
10d7     10d7:	e9 00 00 00 00       	jmp    10dc <.altinstr_replacement+0x10dc>	10d8: R_X86_64_PC32	.text+0x2db039
10dc     10dc:	e9 00 00 00 00       	jmp    10e1 <.altinstr_replacement+0x10e1>	10dd: R_X86_64_PC32	.text+0x2dbac7
10e1     10e1:	e9 00 00 00 00       	jmp    10e6 <.altinstr_replacement+0x10e6>	10e2: R_X86_64_PC32	.text+0x2db9f3
10e6     10e6:	9c                   	pushf
10e7     10e7:	58                   	pop    %rax
10e8     10e8:	fa                   	cli
10e9     10e9:	9c                   	pushf
10ea     10ea:	58                   	pop    %rax
10eb     10eb:	fa                   	cli
10ec     10ec:	9c                   	pushf
10ed     10ed:	58                   	pop    %rax
10ee     10ee:	fa                   	cli
10ef     10ef:	9c                   	pushf
10f0     10f0:	58                   	pop    %rax
10f1     10f1:	fa                   	cli
10f2     10f2:	9c                   	pushf
10f3     10f3:	58                   	pop    %rax
10f4     10f4:	fb                   	sti
10f5     10f5:	9c                   	pushf
10f6     10f6:	58                   	pop    %rax
10f7     10f7:	fa                   	cli
10f8     10f8:	9c                   	pushf
10f9     10f9:	58                   	pop    %rax
10fa     10fa:	fa                   	cli
10fb     10fb:	9c                   	pushf
10fc     10fc:	58                   	pop    %rax
10fd     10fd:	fa                   	cli
10fe     10fe:	9c                   	pushf
10ff     10ff:	58                   	pop    %rax
1100     1100:	fb                   	sti
1101     1101:	9c                   	pushf
1102     1102:	58                   	pop    %rax
1103     1103:	fa                   	cli
1104     1104:	9c                   	pushf
1105     1105:	58                   	pop    %rax
1106     1106:	fb                   	sti
1107     1107:	0f 09                	wbinvd
1109     1109:	fb                   	sti
110a     110a:	9c                   	pushf
110b     110b:	58                   	pop    %rax
110c     110c:	fa                   	cli
110d     110d:	9c                   	pushf
110e     110e:	58                   	pop    %rax
110f     110f:	fb                   	sti
1110     1110:	e9 00 00 00 00       	jmp    1115 <.altinstr_replacement+0x1115>	1111: R_X86_64_PC32	.init.text+0x5f5e6
1115     1115:	9c                   	pushf
1116     1116:	58                   	pop    %rax
1117     1117:	fa                   	cli
1118     1118:	0f 09                	wbinvd
111a     111a:	e9 00 00 00 00       	jmp    111f <.altinstr_replacement+0x111f>	111b: R_X86_64_PC32	.init.text+0x5fc37
111f     111f:	0f ae e8             	lfence
1122     1122:	0f 31                	rdtsc
1124     1124:	0f 01 f9             	rdtscp
1127     1127:	0f ae e8             	lfence
112a     112a:	0f 31                	rdtsc
112c     112c:	0f 01 f9             	rdtscp
112f     112f:	c6 07 00             	movb   $0x0,(%rdi)
1132     1132:	c6 07 00             	movb   $0x0,(%rdi)
1135     1135:	9c                   	pushf
1136     1136:	58                   	pop    %rax
1137     1137:	fa                   	cli
1138     1138:	fb                   	sti
1139     1139:	9c                   	pushf
113a     113a:	58                   	pop    %rax
113b     113b:	fa                   	cli
113c     113c:	fb                   	sti
113d     113d:	9c                   	pushf
113e     113e:	58                   	pop    %rax
113f     113f:	fa                   	cli
1140     1140:	fb                   	sti
1141     1141:	fb                   	sti
1142     1142:	9c                   	pushf
1143     1143:	58                   	pop    %rax
1144     1144:	fa                   	cli
1145     1145:	fb                   	sti
1146     1146:	9c                   	pushf
1147     1147:	58                   	pop    %rax
1148     1148:	fa                   	cli
1149     1149:	9c                   	pushf
114a     114a:	58                   	pop    %rax
114b     114b:	fb                   	sti
114c     114c:	9c                   	pushf
114d     114d:	58                   	pop    %rax
114e     114e:	fa                   	cli
114f     114f:	9c                   	pushf
1150     1150:	58                   	pop    %rax
1151     1151:	fb                   	sti
1152     1152:	9c                   	pushf
1153     1153:	58                   	pop    %rax
1154     1154:	fa                   	cli
1155     1155:	9c                   	pushf
1156     1156:	58                   	pop    %rax
1157     1157:	fb                   	sti
1158     1158:	9c                   	pushf
1159     1159:	58                   	pop    %rax
115a     115a:	fa                   	cli
115b     115b:	9c                   	pushf
115c     115c:	58                   	pop    %rax
115d     115d:	fb                   	sti
115e     115e:	9c                   	pushf
115f     115f:	58                   	pop    %rax
1160     1160:	fa                   	cli
1161     1161:	9c                   	pushf
1162     1162:	58                   	pop    %rax
1163     1163:	fb                   	sti
1164     1164:	87 34 25 00 c3 5f ff 	xchg   %esi,0xffffffffff5fc300
116b     116b:	87 04 25 10 c3 5f ff 	xchg   %eax,0xffffffffff5fc310
1172     1172:	87 04 25 00 c3 5f ff 	xchg   %eax,0xffffffffff5fc300
1179     1179:	9c                   	pushf
117a     117a:	58                   	pop    %rax
117b     117b:	fa                   	cli
117c     117c:	9c                   	pushf
117d     117d:	58                   	pop    %rax
117e     117e:	fb                   	sti
117f     117f:	9c                   	pushf
1180     1180:	58                   	pop    %rax
1181     1181:	fa                   	cli
1182     1182:	9c                   	pushf
1183     1183:	58                   	pop    %rax
1184     1184:	fb                   	sti
1185     1185:	9c                   	pushf
1186     1186:	58                   	pop    %rax
1187     1187:	fa                   	cli
1188     1188:	9c                   	pushf
1189     1189:	58                   	pop    %rax
118a     118a:	fb                   	sti
118b     118b:	87 3c 25 00 c3 5f ff 	xchg   %edi,0xffffffffff5fc300
1192     1192:	87 3c 25 00 c3 5f ff 	xchg   %edi,0xffffffffff5fc300
1199     1199:	87 3c 25 00 c3 5f ff 	xchg   %edi,0xffffffffff5fc300
11a0     11a0:	fb                   	sti
11a1     11a1:	9c                   	pushf
11a2     11a2:	58                   	pop    %rax
11a3     11a3:	fa                   	cli
11a4     11a4:	9c                   	pushf
11a5     11a5:	58                   	pop    %rax
11a6     11a6:	fa                   	cli
11a7     11a7:	fb                   	sti
11a8     11a8:	9c                   	pushf
11a9     11a9:	58                   	pop    %rax
11aa     11aa:	fa                   	cli
11ab     11ab:	9c                   	pushf
11ac     11ac:	58                   	pop    %rax
11ad     11ad:	fb                   	sti
11ae     11ae:	87 b7 00 c0 5f ff    	xchg   %esi,-0xa04000(%rdi)
11b4     11b4:	e9 00 00 00 00       	jmp    11b9 <.altinstr_replacement+0x11b9>	11b5: R_X86_64_PC32	.text+0x2f447f
11b9     11b9:	9c                   	pushf
11ba     11ba:	58                   	pop    %rax
11bb     11bb:	fa                   	cli
11bc     11bc:	9c                   	pushf
11bd     11bd:	58                   	pop    %rax
11be     11be:	fb                   	sti
11bf     11bf:	f3 48 0f b8 c7       	popcnt %rdi,%rax
11c4     11c4:	f3 48 0f b8 c7       	popcnt %rdi,%rax
11c9     11c9:	f3 48 0f b8 c7       	popcnt %rdi,%rax
11ce     11ce:	9c                   	pushf
11cf     11cf:	58                   	pop    %rax
11d0     11d0:	fa                   	cli
11d1     11d1:	9c                   	pushf
11d2     11d2:	58                   	pop    %rax
11d3     11d3:	fb                   	sti
11d4     11d4:	9c                   	pushf
11d5     11d5:	58                   	pop    %rax
11d6     11d6:	fa                   	cli
11d7     11d7:	9c                   	pushf
11d8     11d8:	58                   	pop    %rax
11d9     11d9:	fb                   	sti
11da     11da:	87 b7 00 c0 5f ff    	xchg   %esi,-0xa04000(%rdi)
11e0     11e0:	9c                   	pushf
11e1     11e1:	58                   	pop    %rax
11e2     11e2:	fa                   	cli
11e3     11e3:	9c                   	pushf
11e4     11e4:	58                   	pop    %rax
11e5     11e5:	fb                   	sti
11e6     11e6:	e9 00 00 00 00       	jmp    11eb <.altinstr_replacement+0x11eb>	11e7: R_X86_64_PC32	.text+0x2f867d
11eb     11eb:	0f ae e8             	lfence
11ee     11ee:	0f 31                	rdtsc
11f0     11f0:	0f 01 f9             	rdtscp
11f3     11f3:	e9 00 00 00 00       	jmp    11f8 <.altinstr_replacement+0x11f8>	11f4: R_X86_64_PC32	.text+0x2fa3e5
11f8     11f8:	e8 00 00 00 00       	call   11fd <.altinstr_replacement+0x11fd>	11f9: R_X86_64_PLT32	clear_page_rep-0x4
11fd     11fd:	e8 00 00 00 00       	call   1202 <.altinstr_replacement+0x1202>	11fe: R_X86_64_PLT32	clear_page_erms-0x4
1202     1202:	e9 00 00 00 00       	jmp    1207 <.altinstr_replacement+0x1207>	1203: R_X86_64_PC32	.text+0x2fa68f
1207     1207:	48 89 f8             	mov    %rdi,%rax
120a     120a:	48 89 f8             	mov    %rdi,%rax
120d     120d:	e9 00 00 00 00       	jmp    1212 <.altinstr_replacement+0x1212>	120e: R_X86_64_PC32	.text+0x2fab70
1212     1212:	e9 00 00 00 00       	jmp    1217 <.altinstr_replacement+0x1217>	1213: R_X86_64_PC32	.text+0x2fb00b
1217     1217:	48 89 f8             	mov    %rdi,%rax
121a     121a:	48 89 f8             	mov    %rdi,%rax
121d     121d:	48 89 f8             	mov    %rdi,%rax
1220     1220:	48 89 f8             	mov    %rdi,%rax
1223     1223:	48 89 f8             	mov    %rdi,%rax
1226     1226:	48 89 f8             	mov    %rdi,%rax
1229     1229:	48 89 f8             	mov    %rdi,%rax
122c     122c:	48 89 f8             	mov    %rdi,%rax
122f     122f:	e8 00 00 00 00       	call   1234 <.altinstr_replacement+0x1234>	1230: R_X86_64_PLT32	clear_page_rep-0x4
1234     1234:	e8 00 00 00 00       	call   1239 <.altinstr_replacement+0x1239>	1235: R_X86_64_PLT32	clear_page_erms-0x4
1239     1239:	9c                   	pushf
123a     123a:	58                   	pop    %rax
123b     123b:	fa                   	cli
123c     123c:	9c                   	pushf
123d     123d:	58                   	pop    %rax
123e     123e:	fa                   	cli
123f     123f:	9c                   	pushf
1240     1240:	58                   	pop    %rax
1241     1241:	fb                   	sti
1242     1242:	9c                   	pushf
1243     1243:	58                   	pop    %rax
1244     1244:	fa                   	cli
1245     1245:	e9 00 00 00 00       	jmp    124a <.altinstr_replacement+0x124a>	1246: R_X86_64_PC32	.text+0x2feda7
124a     124a:	9c                   	pushf
124b     124b:	58                   	pop    %rax
124c     124c:	fa                   	cli
124d     124d:	9c                   	pushf
124e     124e:	58                   	pop    %rax
124f     124f:	fb                   	sti
1250     1250:	9c                   	pushf
1251     1251:	58                   	pop    %rax
1252     1252:	fa                   	cli
1253     1253:	c6 07 00             	movb   $0x0,(%rdi)
1256     1256:	9c                   	pushf
1257     1257:	58                   	pop    %rax
1258     1258:	fb                   	sti
1259     1259:	9c                   	pushf
125a     125a:	58                   	pop    %rax
125b     125b:	fb                   	sti
125c     125c:	e9 00 00 00 00       	jmp    1261 <.altinstr_replacement+0x1261>	125d: R_X86_64_PC32	.init.text+0x7423f
1261     1261:	9c                   	pushf
1262     1262:	58                   	pop    %rax
1263     1263:	fa                   	cli
1264     1264:	9c                   	pushf
1265     1265:	58                   	pop    %rax
1266     1266:	fb                   	sti
1267     1267:	9c                   	pushf
1268     1268:	58                   	pop    %rax
1269     1269:	9c                   	pushf
126a     126a:	58                   	pop    %rax
126b     126b:	fa                   	cli
126c     126c:	fb                   	sti
126d     126d:	fb                   	sti
126e     126e:	9c                   	pushf
126f     126f:	58                   	pop    %rax
1270     1270:	fa                   	cli
1271     1271:	e9 00 00 00 00       	jmp    1276 <.altinstr_replacement+0x1276>	1272: R_X86_64_PC32	.text+0x30a493
1276     1276:	0f 01 d9             	vmmcall
1279     1279:	48 31 c0             	xor    %rax,%rax
127c     127c:	e9 00 00 00 00       	jmp    1281 <.altinstr_replacement+0x1281>	127d: R_X86_64_PC32	.text+0x30acf9
1281     1281:	0f 01 d9             	vmmcall
1284     1284:	9c                   	pushf
1285     1285:	58                   	pop    %rax
1286     1286:	fa                   	cli
1287     1287:	e9 00 00 00 00       	jmp    128c <.altinstr_replacement+0x128c>	1288: R_X86_64_PC32	.text+0x30b4ea
128c     128c:	9c                   	pushf
128d     128d:	58                   	pop    %rax
128e     128e:	fb                   	sti
128f     128f:	0f 01 d9             	vmmcall
1292     1292:	e9 00 00 00 00       	jmp    1297 <.altinstr_replacement+0x1297>	1293: R_X86_64_PC32	.text+0x30b5c3
1297     1297:	0f 01 d9             	vmmcall
129a     129a:	9c                   	pushf
129b     129b:	58                   	pop    %rax
129c     129c:	fa                   	cli
129d     129d:	9c                   	pushf
129e     129e:	58                   	pop    %rax
129f     129f:	fb                   	sti
12a0     12a0:	9c                   	pushf
12a1     12a1:	58                   	pop    %rax
12a2     12a2:	fa                   	cli
12a3     12a3:	9c                   	pushf
12a4     12a4:	58                   	pop    %rax
12a5     12a5:	fb                   	sti
12a6     12a6:	e9 00 00 00 00       	jmp    12ab <.altinstr_replacement+0x12ab>	12a7: R_X86_64_PC32	.text+0x30ce58
12ab     12ab:	e9 00 00 00 00       	jmp    12b0 <.altinstr_replacement+0x12b0>	12ac: R_X86_64_PC32	.text+0x30ce65
12b0     12b0:	9c                   	pushf
12b1     12b1:	58                   	pop    %rax
12b2     12b2:	fa                   	cli
12b3     12b3:	9c                   	pushf
12b4     12b4:	58                   	pop    %rax
12b5     12b5:	fb                   	sti
12b6     12b6:	e9 00 00 00 00       	jmp    12bb <.altinstr_replacement+0x12bb>	12b7: R_X86_64_PC32	.text+0x30d551
12bb     12bb:	9c                   	pushf
12bc     12bc:	58                   	pop    %rax
12bd     12bd:	9c                   	pushf
12be     12be:	58                   	pop    %rax
12bf     12bf:	0f ae e8             	lfence
12c2     12c2:	0f 31                	rdtsc
12c4     12c4:	0f 01 f9             	rdtscp
12c7     12c7:	9c                   	pushf
12c8     12c8:	58                   	pop    %rax
12c9     12c9:	9c                   	pushf
12ca     12ca:	58                   	pop    %rax
12cb     12cb:	9c                   	pushf
12cc     12cc:	58                   	pop    %rax
12cd     12cd:	fa                   	cli
12ce     12ce:	9c                   	pushf
12cf     12cf:	58                   	pop    %rax
12d0     12d0:	fb                   	sti
12d1     12d1:	9c                   	pushf
12d2     12d2:	58                   	pop    %rax
12d3     12d3:	fa                   	cli
12d4     12d4:	9c                   	pushf
12d5     12d5:	58                   	pop    %rax
12d6     12d6:	fb                   	sti
12d7     12d7:	9c                   	pushf
12d8     12d8:	58                   	pop    %rax
12d9     12d9:	fa                   	cli
12da     12da:	9c                   	pushf
12db     12db:	58                   	pop    %rax
12dc     12dc:	fb                   	sti
12dd     12dd:	9c                   	pushf
12de     12de:	58                   	pop    %rax
12df     12df:	fa                   	cli
12e0     12e0:	9c                   	pushf
12e1     12e1:	58                   	pop    %rax
12e2     12e2:	fb                   	sti
12e3     12e3:	0f 20 d8             	mov    %cr3,%rax
12e6     12e6:	48 89 f8             	mov    %rdi,%rax
12e9     12e9:	48 89 f8             	mov    %rdi,%rax
12ec     12ec:	0f 09                	wbinvd
12ee     12ee:	f3 0f b8 c7          	popcnt %edi,%eax
12f2     12f2:	9c                   	pushf
12f3     12f3:	58                   	pop    %rax
12f4     12f4:	fa                   	cli
12f5     12f5:	9c                   	pushf
12f6     12f6:	58                   	pop    %rax
12f7     12f7:	fb                   	sti
12f8     12f8:	e9 00 00 00 00       	jmp    12fd <.altinstr_replacement+0x12fd>	12f9: R_X86_64_PC32	.init.text+0x7e2d1
12fd     12fd:	e8 00 00 00 00       	call   1302 <.altinstr_replacement+0x1302>	12fe: R_X86_64_PLT32	clear_page_rep-0x4
1302     1302:	e8 00 00 00 00       	call   1307 <.altinstr_replacement+0x1307>	1303: R_X86_64_PLT32	clear_page_erms-0x4
1307     1307:	0f 22 df             	mov    %rdi,%cr3
130a     130a:	e9 00 00 00 00       	jmp    130f <.altinstr_replacement+0x130f>	130b: R_X86_64_PC32	.text+0x318541
130f     130f:	e9 00 00 00 00       	jmp    1314 <.altinstr_replacement+0x1314>	1310: R_X86_64_PC32	.text+0x318bf9
1314     1314:	e9 00 00 00 00       	jmp    1319 <.altinstr_replacement+0x1319>	1315: R_X86_64_PC32	.text+0x318d00
1319     1319:	48 89 f8             	mov    %rdi,%rax
131c     131c:	48 89 f8             	mov    %rdi,%rax
131f     131f:	48 89 f8             	mov    %rdi,%rax
1322     1322:	48 89 f8             	mov    %rdi,%rax
1325     1325:	48 89 f8             	mov    %rdi,%rax
1328     1328:	48 89 f8             	mov    %rdi,%rax
132b     132b:	48 89 f8             	mov    %rdi,%rax
132e     132e:	48 89 f8             	mov    %rdi,%rax
1331     1331:	48 89 f8             	mov    %rdi,%rax
1334     1334:	48 89 f8             	mov    %rdi,%rax
1337     1337:	e9 00 00 00 00       	jmp    133c <.altinstr_replacement+0x133c>	1338: R_X86_64_PC32	.text.unlikely+0x2b95d
133c     133c:	e9 00 00 00 00       	jmp    1341 <.altinstr_replacement+0x1341>	133d: R_X86_64_PC32	.text.unlikely+0x2b923
1341     1341:	e9 00 00 00 00       	jmp    1346 <.altinstr_replacement+0x1346>	1342: R_X86_64_PC32	.text.unlikely+0x2baa1
1346     1346:	e9 00 00 00 00       	jmp    134b <.altinstr_replacement+0x134b>	1347: R_X86_64_PC32	.text.unlikely+0x2ba67
134b     134b:	48 89 f8             	mov    %rdi,%rax
134e     134e:	48 89 f8             	mov    %rdi,%rax
1351     1351:	48 89 f8             	mov    %rdi,%rax
1354     1354:	48 89 f8             	mov    %rdi,%rax
1357     1357:	48 89 f8             	mov    %rdi,%rax
135a     135a:	e9 00 00 00 00       	jmp    135f <.altinstr_replacement+0x135f>	135b: R_X86_64_PC32	.text.unlikely+0x2c136
135f     135f:	48 89 f8             	mov    %rdi,%rax
1362     1362:	48 89 f8             	mov    %rdi,%rax
1365     1365:	e9 00 00 00 00       	jmp    136a <.altinstr_replacement+0x136a>	1366: R_X86_64_PC32	.meminit.text+0x2376
136a     136a:	48 89 f8             	mov    %rdi,%rax
136d     136d:	e9 00 00 00 00       	jmp    1372 <.altinstr_replacement+0x1372>	136e: R_X86_64_PC32	.meminit.text+0x33b7
1372     1372:	48 89 f8             	mov    %rdi,%rax
1375     1375:	e9 00 00 00 00       	jmp    137a <.altinstr_replacement+0x137a>	1376: R_X86_64_PC32	.text+0x31a49e
137a     137a:	48 89 f8             	mov    %rdi,%rax
137d     137d:	e9 00 00 00 00       	jmp    1382 <.altinstr_replacement+0x1382>	137e: R_X86_64_PC32	.init.text+0x7f948
1382     1382:	e9 00 00 00 00       	jmp    1387 <.altinstr_replacement+0x1387>	1383: R_X86_64_PC32	.text.unlikely+0x2c5e2
1387     1387:	e9 00 00 00 00       	jmp    138c <.altinstr_replacement+0x138c>	1388: R_X86_64_PC32	.meminit.text+0x3af9
138c     138c:	e9 00 00 00 00       	jmp    1391 <.altinstr_replacement+0x1391>	138d: R_X86_64_PC32	.init.text+0x7fc0a
1391     1391:	e9 00 00 00 00       	jmp    1396 <.altinstr_replacement+0x1396>	1392: R_X86_64_PC32	.init.text+0x7fd47
1396     1396:	48 89 f8             	mov    %rdi,%rax
1399     1399:	48 89 f8             	mov    %rdi,%rax
139c     139c:	48 89 f8             	mov    %rdi,%rax
139f     139f:	48 89 f8             	mov    %rdi,%rax
13a2     13a2:	48 89 f8             	mov    %rdi,%rax
13a5     13a5:	48 89 f8             	mov    %rdi,%rax
13a8     13a8:	48 89 f8             	mov    %rdi,%rax
13ab     13ab:	48 89 f8             	mov    %rdi,%rax
13ae     13ae:	48 89 f8             	mov    %rdi,%rax
13b1     13b1:	48 89 f8             	mov    %rdi,%rax
13b4     13b4:	48 89 f8             	mov    %rdi,%rax
13b7     13b7:	48 89 f8             	mov    %rdi,%rax
13ba     13ba:	48 89 f8             	mov    %rdi,%rax
13bd     13bd:	48 89 f8             	mov    %rdi,%rax
13c0     13c0:	e9 00 00 00 00       	jmp    13c5 <.altinstr_replacement+0x13c5>	13c1: R_X86_64_PC32	.text+0x31b6d4
13c5     13c5:	e9 00 00 00 00       	jmp    13ca <.altinstr_replacement+0x13ca>	13c6: R_X86_64_PC32	.text+0x31b734
13ca     13ca:	e9 00 00 00 00       	jmp    13cf <.altinstr_replacement+0x13cf>	13cb: R_X86_64_PC32	.text+0x31b80c
13cf     13cf:	48 89 f8             	mov    %rdi,%rax
13d2     13d2:	48 89 f8             	mov    %rdi,%rax
13d5     13d5:	e9 00 00 00 00       	jmp    13da <.altinstr_replacement+0x13da>	13d6: R_X86_64_PC32	.text+0x31b885
13da     13da:	48 89 f8             	mov    %rdi,%rax
13dd     13dd:	48 89 f8             	mov    %rdi,%rax
13e0     13e0:	48 89 f8             	mov    %rdi,%rax
13e3     13e3:	e9 00 00 00 00       	jmp    13e8 <.altinstr_replacement+0x13e8>	13e4: R_X86_64_PC32	.text+0x31bcef
13e8     13e8:	e9 00 00 00 00       	jmp    13ed <.altinstr_replacement+0x13ed>	13e9: R_X86_64_PC32	.text+0x31bfac
13ed     13ed:	e9 00 00 00 00       	jmp    13f2 <.altinstr_replacement+0x13f2>	13ee: R_X86_64_PC32	.text+0x31c035
13f2     13f2:	48 89 f8             	mov    %rdi,%rax
13f5     13f5:	48 89 f8             	mov    %rdi,%rax
13f8     13f8:	48 89 f8             	mov    %rdi,%rax
13fb     13fb:	48 89 f8             	mov    %rdi,%rax
13fe     13fe:	48 89 f8             	mov    %rdi,%rax
1401     1401:	e9 00 00 00 00       	jmp    1406 <.altinstr_replacement+0x1406>	1402: R_X86_64_PC32	.text+0x31c98d
1406     1406:	e9 00 00 00 00       	jmp    140b <.altinstr_replacement+0x140b>	1407: R_X86_64_PC32	.text+0x31c9c6
140b     140b:	48 89 f8             	mov    %rdi,%rax
140e     140e:	e9 00 00 00 00       	jmp    1413 <.altinstr_replacement+0x1413>	140f: R_X86_64_PC32	.text+0x31c94d
1413     1413:	e9 00 00 00 00       	jmp    1418 <.altinstr_replacement+0x1418>	1414: R_X86_64_PC32	.text+0x31c9a0
1418     1418:	48 89 f8             	mov    %rdi,%rax
141b     141b:	e9 00 00 00 00       	jmp    1420 <.altinstr_replacement+0x1420>	141c: R_X86_64_PC32	.text+0x31c971
1420     1420:	e9 00 00 00 00       	jmp    1425 <.altinstr_replacement+0x1425>	1421: R_X86_64_PC32	.text+0x31c9b3
1425     1425:	e9 00 00 00 00       	jmp    142a <.altinstr_replacement+0x142a>	1426: R_X86_64_PC32	.text+0x31cc40
142a     142a:	48 89 f8             	mov    %rdi,%rax
142d     142d:	48 89 f8             	mov    %rdi,%rax
1430     1430:	48 89 f8             	mov    %rdi,%rax
1433     1433:	48 89 f8             	mov    %rdi,%rax
1436     1436:	48 89 f8             	mov    %rdi,%rax
1439     1439:	48 89 f8             	mov    %rdi,%rax
143c     143c:	48 89 f8             	mov    %rdi,%rax
143f     143f:	48 89 f8             	mov    %rdi,%rax
1442     1442:	48 89 f8             	mov    %rdi,%rax
1445     1445:	48 89 f8             	mov    %rdi,%rax
1448     1448:	e9 00 00 00 00       	jmp    144d <.altinstr_replacement+0x144d>	1449: R_X86_64_PC32	.text+0x31e7de
144d     144d:	48 89 f8             	mov    %rdi,%rax
1450     1450:	0f 20 d8             	mov    %cr3,%rax
1453     1453:	48 89 f8             	mov    %rdi,%rax
1456     1456:	e9 00 00 00 00       	jmp    145b <.altinstr_replacement+0x145b>	1457: R_X86_64_PC32	.text+0x31e9b4
145b     145b:	48 89 f8             	mov    %rdi,%rax
145e     145e:	48 89 f8             	mov    %rdi,%rax
1461     1461:	48 89 f8             	mov    %rdi,%rax
1464     1464:	48 89 f8             	mov    %rdi,%rax
1467     1467:	48 89 f8             	mov    %rdi,%rax
146a     146a:	48 89 f8             	mov    %rdi,%rax
146d     146d:	48 89 f8             	mov    %rdi,%rax
1470     1470:	48 89 f8             	mov    %rdi,%rax
1473     1473:	0f 20 d8             	mov    %cr3,%rax
1476     1476:	48 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbp
1480     1480:	fb                   	sti
1481     1481:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
148b     148b:	9c                   	pushf
148c     148c:	58                   	pop    %rax
148d     148d:	fa                   	cli
148e     148e:	e9 00 00 00 00       	jmp    1493 <.altinstr_replacement+0x1493>	148f: R_X86_64_PC32	.text+0x31fe55
1493     1493:	e9 00 00 00 00       	jmp    1498 <.altinstr_replacement+0x1498>	1494: R_X86_64_PC32	.text+0x31ff74
1498     1498:	9c                   	pushf
1499     1499:	58                   	pop    %rax
149a     149a:	e9 00 00 00 00       	jmp    149f <.altinstr_replacement+0x149f>	149b: R_X86_64_PC32	.text+0x320202
149f     149f:	fb                   	sti
14a0     14a0:	fb                   	sti
14a1     14a1:	e9 00 00 00 00       	jmp    14a6 <.altinstr_replacement+0x14a6>	14a2: R_X86_64_PC32	.text+0x320c08
14a6     14a6:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
14b0     14b0:	e9 00 00 00 00       	jmp    14b5 <.altinstr_replacement+0x14b5>	14b1: R_X86_64_PC32	.text+0x321141
14b5     14b5:	48 89 f8             	mov    %rdi,%rax
14b8     14b8:	48 89 f8             	mov    %rdi,%rax
14bb     14bb:	48 89 f8             	mov    %rdi,%rax
14be     14be:	48 89 f8             	mov    %rdi,%rax
14c1     14c1:	9c                   	pushf
14c2     14c2:	58                   	pop    %rax
14c3     14c3:	48 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbp
14cd     14cd:	0f 20 d0             	mov    %cr2,%rax
14d0     14d0:	0f 0d 88 60 03 00 00 	prefetchw 0x360(%rax)
14d7     14d7:	9c                   	pushf
14d8     14d8:	58                   	pop    %rax
14d9     14d9:	fa                   	cli
14da     14da:	e9 00 00 00 00       	jmp    14df <.altinstr_replacement+0x14df>	14db: R_X86_64_PC32	.text.unlikely+0x2d1d4
14df     14df:	48 89 f8             	mov    %rdi,%rax
14e2     14e2:	0f 20 d8             	mov    %cr3,%rax
14e5     14e5:	48 89 f8             	mov    %rdi,%rax
14e8     14e8:	48 89 f8             	mov    %rdi,%rax
14eb     14eb:	e9 00 00 00 00       	jmp    14f0 <.altinstr_replacement+0x14f0>	14ec: R_X86_64_PC32	.text+0x3226e9
14f0     14f0:	e9 00 00 00 00       	jmp    14f5 <.altinstr_replacement+0x14f5>	14f1: R_X86_64_PC32	.text+0x3226f4
14f5     14f5:	48 89 f8             	mov    %rdi,%rax
14f8     14f8:	48 89 f8             	mov    %rdi,%rax
14fb     14fb:	e9 00 00 00 00       	jmp    1500 <.altinstr_replacement+0x1500>	14fc: R_X86_64_PC32	.text+0x323c09
1500     1500:	0f 20 d0             	mov    %cr2,%rax
1503     1503:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
150d     150d:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
1517     1517:	e9 00 00 00 00       	jmp    151c <.altinstr_replacement+0x151c>	1518: R_X86_64_PC32	.text+0x324c35
151c     151c:	e9 00 00 00 00       	jmp    1521 <.altinstr_replacement+0x1521>	151d: R_X86_64_PC32	.text+0x324ad6
1521     1521:	9c                   	pushf
1522     1522:	58                   	pop    %rax
1523     1523:	fa                   	cli
1524     1524:	9c                   	pushf
1525     1525:	58                   	pop    %rax
1526     1526:	fb                   	sti
1527     1527:	e9 00 00 00 00       	jmp    152c <.altinstr_replacement+0x152c>	1528: R_X86_64_PC32	.text+0x324e6f
152c     152c:	48 89 f8             	mov    %rdi,%rax
152f     152f:	48 89 f8             	mov    %rdi,%rax
1532     1532:	e9 00 00 00 00       	jmp    1537 <.altinstr_replacement+0x1537>	1533: R_X86_64_PC32	.text+0x324fcb
1537     1537:	48 89 f8             	mov    %rdi,%rax
153a     153a:	48 89 f8             	mov    %rdi,%rax
153d     153d:	48 89 f8             	mov    %rdi,%rax
1540     1540:	48 89 f8             	mov    %rdi,%rax
1543     1543:	48 89 f8             	mov    %rdi,%rax
1546     1546:	48 89 f8             	mov    %rdi,%rax
1549     1549:	48 89 f8             	mov    %rdi,%rax
154c     154c:	48 89 f8             	mov    %rdi,%rax
154f     154f:	48 89 f8             	mov    %rdi,%rax
1552     1552:	48 89 f8             	mov    %rdi,%rax
1555     1555:	48 89 f8             	mov    %rdi,%rax
1558     1558:	48 89 f8             	mov    %rdi,%rax
155b     155b:	48 89 f8             	mov    %rdi,%rax
155e     155e:	e9 00 00 00 00       	jmp    1563 <.altinstr_replacement+0x1563>	155f: R_X86_64_PC32	.text+0x327ce9
1563     1563:	e9 00 00 00 00       	jmp    1568 <.altinstr_replacement+0x1568>	1564: R_X86_64_PC32	.text+0x327d72
1568     1568:	e9 00 00 00 00       	jmp    156d <.altinstr_replacement+0x156d>	1569: R_X86_64_PC32	.text+0x3281a4
156d     156d:	e9 00 00 00 00       	jmp    1572 <.altinstr_replacement+0x1572>	156e: R_X86_64_PC32	.text+0x3281a4
1572     1572:	9c                   	pushf
1573     1573:	58                   	pop    %rax
1574     1574:	e9 00 00 00 00       	jmp    1579 <.altinstr_replacement+0x1579>	1575: R_X86_64_PC32	.text+0x328805
1579     1579:	0f 22 df             	mov    %rdi,%cr3
157c     157c:	0f 20 d8             	mov    %cr3,%rax
157f     157f:	9c                   	pushf
1580     1580:	58                   	pop    %rax
1581     1581:	9c                   	pushf
1582     1582:	58                   	pop    %rax
1583     1583:	0f 20 d8             	mov    %cr3,%rax
1586     1586:	0f 30                	wrmsr
1588     1588:	e9 00 00 00 00       	jmp    158d <.altinstr_replacement+0x158d>	1589: R_X86_64_PC32	.text+0x328fa5
158d     158d:	0f 30                	wrmsr
158f     158f:	e9 00 00 00 00       	jmp    1594 <.altinstr_replacement+0x1594>	1590: R_X86_64_PC32	.text+0x32927f
1594     1594:	9c                   	pushf
1595     1595:	58                   	pop    %rax
1596     1596:	fa                   	cli
1597     1597:	9c                   	pushf
1598     1598:	58                   	pop    %rax
1599     1599:	fb                   	sti
159a     159a:	9c                   	pushf
159b     159b:	58                   	pop    %rax
159c     159c:	0f 20 d8             	mov    %cr3,%rax
159f     159f:	0f 22 df             	mov    %rdi,%cr3
15a2     15a2:	9c                   	pushf
15a3     15a3:	58                   	pop    %rax
15a4     15a4:	fa                   	cli
15a5     15a5:	fb                   	sti
15a6     15a6:	e9 00 00 00 00       	jmp    15ab <.altinstr_replacement+0x15ab>	15a7: R_X86_64_PC32	.text+0x32a0fd
15ab     15ab:	e9 00 00 00 00       	jmp    15b0 <.altinstr_replacement+0x15b0>	15ac: R_X86_64_PC32	.text+0x32a263
15b0     15b0:	e9 00 00 00 00       	jmp    15b5 <.altinstr_replacement+0x15b5>	15b1: R_X86_64_PC32	.text+0x32a3fd
15b5     15b5:	9c                   	pushf
15b6     15b6:	58                   	pop    %rax
15b7     15b7:	fa                   	cli
15b8     15b8:	9c                   	pushf
15b9     15b9:	58                   	pop    %rax
15ba     15ba:	fb                   	sti
15bb     15bb:	9c                   	pushf
15bc     15bc:	58                   	pop    %rax
15bd     15bd:	9c                   	pushf
15be     15be:	58                   	pop    %rax
15bf     15bf:	fa                   	cli
15c0     15c0:	fb                   	sti
15c1     15c1:	0f 20 d8             	mov    %cr3,%rax
15c4     15c4:	48 89 f8             	mov    %rdi,%rax
15c7     15c7:	48 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbp
15d1     15d1:	e9 00 00 00 00       	jmp    15d6 <.altinstr_replacement+0x15d6>	15d2: R_X86_64_PC32	.text+0x32b01e
15d6     15d6:	48 89 f8             	mov    %rdi,%rax
15d9     15d9:	48 89 f8             	mov    %rdi,%rax
15dc     15dc:	0f 09                	wbinvd
15de     15de:	48 89 f8             	mov    %rdi,%rax
15e1     15e1:	9c                   	pushf
15e2     15e2:	58                   	pop    %rax
15e3     15e3:	66 0f ae 3b          	clflushopt (%rbx)
15e7     15e7:	66 0f ae 3b          	clflushopt (%rbx)
15eb     15eb:	48 89 f8             	mov    %rdi,%rax
15ee     15ee:	48 89 f8             	mov    %rdi,%rax
15f1     15f1:	48 89 f8             	mov    %rdi,%rax
15f4     15f4:	48 89 f8             	mov    %rdi,%rax
15f7     15f7:	48 89 f8             	mov    %rdi,%rax
15fa     15fa:	48 89 f8             	mov    %rdi,%rax
15fd     15fd:	48 89 f8             	mov    %rdi,%rax
1600     1600:	48 89 f8             	mov    %rdi,%rax
1603     1603:	48 89 f8             	mov    %rdi,%rax
1606     1606:	48 89 f8             	mov    %rdi,%rax
1609     1609:	48 89 f8             	mov    %rdi,%rax
160c     160c:	48 89 f8             	mov    %rdi,%rax
160f     160f:	48 89 f8             	mov    %rdi,%rax
1612     1612:	48 89 f8             	mov    %rdi,%rax
1615     1615:	48 89 f8             	mov    %rdi,%rax
1618     1618:	48 89 f8             	mov    %rdi,%rax
161b     161b:	48 89 f8             	mov    %rdi,%rax
161e     161e:	48 89 f8             	mov    %rdi,%rax
1621     1621:	48 89 f8             	mov    %rdi,%rax
1624     1624:	e9 00 00 00 00       	jmp    1629 <.altinstr_replacement+0x1629>	1625: R_X86_64_PC32	.text+0x32da54
1629     1629:	e9 00 00 00 00       	jmp    162e <.altinstr_replacement+0x162e>	162a: R_X86_64_PC32	.text+0x32dbbc
162e     162e:	48 89 f8             	mov    %rdi,%rax
1631     1631:	48 89 f8             	mov    %rdi,%rax
1634     1634:	48 89 f8             	mov    %rdi,%rax
1637     1637:	48 89 f8             	mov    %rdi,%rax
163a     163a:	48 89 f8             	mov    %rdi,%rax
163d     163d:	e9 00 00 00 00       	jmp    1642 <.altinstr_replacement+0x1642>	163e: R_X86_64_PC32	.text+0x32e271
1642     1642:	48 89 f8             	mov    %rdi,%rax
1645     1645:	48 89 f8             	mov    %rdi,%rax
1648     1648:	48 89 f8             	mov    %rdi,%rax
164b     164b:	48 89 f8             	mov    %rdi,%rax
164e     164e:	48 89 f8             	mov    %rdi,%rax
1651     1651:	48 89 f8             	mov    %rdi,%rax
1654     1654:	48 89 f8             	mov    %rdi,%rax
1657     1657:	9c                   	pushf
1658     1658:	58                   	pop    %rax
1659     1659:	e9 00 00 00 00       	jmp    165e <.altinstr_replacement+0x165e>	165a: R_X86_64_PC32	.text+0x32f035
165e     165e:	48 89 f8             	mov    %rdi,%rax
1661     1661:	66 41 0f ae 7d 00    	clflushopt 0x0(%r13)
1667     1667:	48 89 f8             	mov    %rdi,%rax
166a     166a:	48 89 f8             	mov    %rdi,%rax
166d     166d:	48 89 f8             	mov    %rdi,%rax
1670     1670:	48 89 f8             	mov    %rdi,%rax
1673     1673:	48 89 f8             	mov    %rdi,%rax
1676     1676:	48 89 f8             	mov    %rdi,%rax
1679     1679:	48 89 f8             	mov    %rdi,%rax
167c     167c:	48 89 f8             	mov    %rdi,%rax
167f     167f:	48 89 f8             	mov    %rdi,%rax
1682     1682:	48 89 f8             	mov    %rdi,%rax
1685     1685:	48 89 f8             	mov    %rdi,%rax
1688     1688:	48 89 f8             	mov    %rdi,%rax
168b     168b:	48 89 f8             	mov    %rdi,%rax
168e     168e:	48 89 f8             	mov    %rdi,%rax
1691     1691:	48 89 f8             	mov    %rdi,%rax
1694     1694:	e9 00 00 00 00       	jmp    1699 <.altinstr_replacement+0x1699>	1695: R_X86_64_PC32	.text+0x3341ab
1699     1699:	48 89 f8             	mov    %rdi,%rax
169c     169c:	48 89 f8             	mov    %rdi,%rax
169f     169f:	48 89 f8             	mov    %rdi,%rax
16a2     16a2:	48 89 f8             	mov    %rdi,%rax
16a5     16a5:	e9 00 00 00 00       	jmp    16aa <.altinstr_replacement+0x16aa>	16a6: R_X86_64_PC32	.init.text+0x82d47
16aa     16aa:	48 ba 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rdx
16b4     16b4:	48 89 f8             	mov    %rdi,%rax
16b7     16b7:	48 89 f8             	mov    %rdi,%rax
16ba     16ba:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
16c4     16c4:	e9 00 00 00 00       	jmp    16c9 <.altinstr_replacement+0x16c9>	16c5: R_X86_64_PC32	.init.text+0x8306e
16c9     16c9:	e9 00 00 00 00       	jmp    16ce <.altinstr_replacement+0x16ce>	16ca: R_X86_64_PC32	.init.text+0x830ce
16ce     16ce:	e9 00 00 00 00       	jmp    16d3 <.altinstr_replacement+0x16d3>	16cf: R_X86_64_PC32	.init.text+0x83104
16d3     16d3:	48 89 f8             	mov    %rdi,%rax
16d6     16d6:	48 89 f8             	mov    %rdi,%rax
16d9     16d9:	48 89 f8             	mov    %rdi,%rax
16dc     16dc:	48 89 f8             	mov    %rdi,%rax
16df     16df:	48 89 f8             	mov    %rdi,%rax
16e2     16e2:	48 89 f8             	mov    %rdi,%rax
16e5     16e5:	48 89 f8             	mov    %rdi,%rax
16e8     16e8:	0f 22 df             	mov    %rdi,%cr3
16eb     16eb:	48 89 f8             	mov    %rdi,%rax
16ee     16ee:	48 89 f8             	mov    %rdi,%rax
16f1     16f1:	48 89 f8             	mov    %rdi,%rax
16f4     16f4:	48 89 f8             	mov    %rdi,%rax
16f7     16f7:	48 89 f8             	mov    %rdi,%rax
16fa     16fa:	48 89 f8             	mov    %rdi,%rax
16fd     16fd:	48 89 f8             	mov    %rdi,%rax
1700     1700:	48 89 f8             	mov    %rdi,%rax
1703     1703:	48 89 f8             	mov    %rdi,%rax
1706     1706:	e9 00 00 00 00       	jmp    170b <.altinstr_replacement+0x170b>	1707: R_X86_64_PC32	.init.text+0x8c52b
170b     170b:	e9 00 00 00 00       	jmp    1710 <.altinstr_replacement+0x1710>	170c: R_X86_64_PC32	.text+0x3415e2
1710     1710:	e9 00 00 00 00       	jmp    1715 <.altinstr_replacement+0x1715>	1711: R_X86_64_PC32	.text+0x341678
1715     1715:	e9 00 00 00 00       	jmp    171a <.altinstr_replacement+0x171a>	1716: R_X86_64_PC32	.text+0x3418e5
171a     171a:	e9 00 00 00 00       	jmp    171f <.altinstr_replacement+0x171f>	171b: R_X86_64_PC32	.text+0x341b9e
171f     171f:	48 89 f8             	mov    %rdi,%rax
1722     1722:	48 89 f8             	mov    %rdi,%rax
1725     1725:	e9 00 00 00 00       	jmp    172a <.altinstr_replacement+0x172a>	1726: R_X86_64_PC32	.text+0x341d2e
172a     172a:	e9 00 00 00 00       	jmp    172f <.altinstr_replacement+0x172f>	172b: R_X86_64_PC32	.text+0x341dc1
172f     172f:	48 89 f8             	mov    %rdi,%rax
1732     1732:	48 89 f8             	mov    %rdi,%rax
1735     1735:	48 89 f8             	mov    %rdi,%rax
1738     1738:	48 89 f8             	mov    %rdi,%rax
173b     173b:	48 89 f8             	mov    %rdi,%rax
173e     173e:	48 89 f8             	mov    %rdi,%rax
1741     1741:	48 89 f8             	mov    %rdi,%rax
1744     1744:	48 89 f8             	mov    %rdi,%rax
1747     1747:	48 89 f8             	mov    %rdi,%rax
174a     174a:	e9 00 00 00 00       	jmp    174f <.altinstr_replacement+0x174f>	174b: R_X86_64_PC32	.text+0x342334
174f     174f:	48 89 f8             	mov    %rdi,%rax
1752     1752:	48 89 f8             	mov    %rdi,%rax
1755     1755:	e9 00 00 00 00       	jmp    175a <.altinstr_replacement+0x175a>	1756: R_X86_64_PC32	.text+0x342865
175a     175a:	e9 00 00 00 00       	jmp    175f <.altinstr_replacement+0x175f>	175b: R_X86_64_PC32	.text.unlikely+0x2ff8b
175f     175f:	e9 00 00 00 00       	jmp    1764 <.altinstr_replacement+0x1764>	1760: R_X86_64_PC32	.text+0x3429cc
1764     1764:	0f 09                	wbinvd
1766     1766:	48 89 f8             	mov    %rdi,%rax
1769     1769:	48 89 f8             	mov    %rdi,%rax
176c     176c:	48 89 f8             	mov    %rdi,%rax
176f     176f:	48 89 f8             	mov    %rdi,%rax
1772     1772:	e9 00 00 00 00       	jmp    1777 <.altinstr_replacement+0x1777>	1773: R_X86_64_PC32	.text.unlikely+0x301d6
1777     1777:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
1781     1781:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
178b     178b:	49 be 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r14
1795     1795:	0f 01 cb             	stac
1798     1798:	0f ae e8             	lfence
179b     179b:	0f 01 ca             	clac
179e     179e:	0f 01 ca             	clac
17a1     17a1:	49 be 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r14
17ab     17ab:	0f 01 cb             	stac
17ae     17ae:	0f ae e8             	lfence
17b1     17b1:	e9 00 00 00 00       	jmp    17b6 <.altinstr_replacement+0x17b6>	17b2: R_X86_64_PC32	.text+0x414c0b
17b6     17b6:	0f 01 ca             	clac
17b9     17b9:	0f 01 ca             	clac
17bc     17bc:	0f 30                	wrmsr
17be     17be:	48 89 f8             	mov    %rdi,%rax
17c1     17c1:	e9 00 00 00 00       	jmp    17c6 <.altinstr_replacement+0x17c6>	17c2: R_X86_64_PC32	.text+0x415fa6
17c6     17c6:	48 89 f8             	mov    %rdi,%rax
17c9     17c9:	e9 00 00 00 00       	jmp    17ce <.altinstr_replacement+0x17ce>	17ca: R_X86_64_PC32	.init.text+0x96244
17ce     17ce:	e9 00 00 00 00       	jmp    17d3 <.altinstr_replacement+0x17d3>	17cf: R_X86_64_PC32	.init.text+0x96354
17d3     17d3:	48 89 f8             	mov    %rdi,%rax
17d6     17d6:	e9 00 00 00 00       	jmp    17db <.altinstr_replacement+0x17db>	17d7: R_X86_64_PC32	.init.text+0x9644a
17db     17db:	48 89 f8             	mov    %rdi,%rax
17de     17de:	48 89 f8             	mov    %rdi,%rax
17e1     17e1:	48 89 f8             	mov    %rdi,%rax
17e4     17e4:	48 89 f8             	mov    %rdi,%rax
17e7     17e7:	9c                   	pushf
17e8     17e8:	58                   	pop    %rax
17e9     17e9:	fa                   	cli
17ea     17ea:	9c                   	pushf
17eb     17eb:	58                   	pop    %rax
17ec     17ec:	fb                   	sti
17ed     17ed:	0f 30                	wrmsr
17ef     17ef:	0f 30                	wrmsr
17f1     17f1:	0f 30                	wrmsr
17f3     17f3:	0f 30                	wrmsr
17f5     17f5:	0f 30                	wrmsr
17f7     17f7:	0f 30                	wrmsr
17f9     17f9:	0f 30                	wrmsr
17fb     17fb:	0f 30                	wrmsr
17fd     17fd:	0f 30                	wrmsr
17ff     17ff:	9c                   	pushf
1800     1800:	58                   	pop    %rax
1801     1801:	fa                   	cli
1802     1802:	9c                   	pushf
1803     1803:	58                   	pop    %rax
1804     1804:	fb                   	sti
1805     1805:	0f 30                	wrmsr
1807     1807:	0f 30                	wrmsr
1809     1809:	0f 30                	wrmsr
180b     180b:	0f 30                	wrmsr
180d     180d:	0f 30                	wrmsr
180f     180f:	0f 30                	wrmsr
1811     1811:	0f 30                	wrmsr
1813     1813:	0f 30                	wrmsr
1815     1815:	0f 30                	wrmsr
1817     1817:	0f 30                	wrmsr
1819     1819:	0f 30                	wrmsr
181b     181b:	0f 30                	wrmsr
181d     181d:	9c                   	pushf
181e     181e:	58                   	pop    %rax
181f     181f:	fa                   	cli
1820     1820:	9c                   	pushf
1821     1821:	58                   	pop    %rax
1822     1822:	fb                   	sti
1823     1823:	9c                   	pushf
1824     1824:	58                   	pop    %rax
1825     1825:	fa                   	cli
1826     1826:	9c                   	pushf
1827     1827:	58                   	pop    %rax
1828     1828:	fb                   	sti
1829     1829:	0f 30                	wrmsr
182b     182b:	0f 30                	wrmsr
182d     182d:	0f 30                	wrmsr
182f     182f:	9c                   	pushf
1830     1830:	58                   	pop    %rax
1831     1831:	fa                   	cli
1832     1832:	9c                   	pushf
1833     1833:	58                   	pop    %rax
1834     1834:	fb                   	sti
1835     1835:	9c                   	pushf
1836     1836:	58                   	pop    %rax
1837     1837:	fa                   	cli
1838     1838:	9c                   	pushf
1839     1839:	58                   	pop    %rax
183a     183a:	fb                   	sti
183b     183b:	9c                   	pushf
183c     183c:	58                   	pop    %rax
183d     183d:	fb                   	sti
183e     183e:	e9 00 00 00 00       	jmp    1843 <.altinstr_replacement+0x1843>	183f: R_X86_64_PC32	.text+0x42090f
1843     1843:	e9 00 00 00 00       	jmp    1848 <.altinstr_replacement+0x1848>	1844: R_X86_64_PC32	.text+0x4210bf
1848     1848:	e9 00 00 00 00       	jmp    184d <.altinstr_replacement+0x184d>	1849: R_X86_64_PC32	.text+0x421127
184d     184d:	48 b9 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rcx
1857     1857:	9c                   	pushf
1858     1858:	58                   	pop    %rax
1859     1859:	fa                   	cli
185a     185a:	9c                   	pushf
185b     185b:	58                   	pop    %rax
185c     185c:	fb                   	sti
185d     185d:	e9 00 00 00 00       	jmp    1862 <.altinstr_replacement+0x1862>	185e: R_X86_64_PC32	.text+0x42b853
1862     1862:	e9 00 00 00 00       	jmp    1867 <.altinstr_replacement+0x1867>	1863: R_X86_64_PC32	.text+0x42cdd4
1867     1867:	e9 00 00 00 00       	jmp    186c <.altinstr_replacement+0x186c>	1868: R_X86_64_PC32	.text+0x42fe46
186c     186c:	49 be 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r14
1876     1876:	9c                   	pushf
1877     1877:	58                   	pop    %rax
1878     1878:	fa                   	cli
1879     1879:	fb                   	sti
187a     187a:	9c                   	pushf
187b     187b:	58                   	pop    %rax
187c     187c:	fa                   	cli
187d     187d:	fb                   	sti
187e     187e:	49 be 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r14
1888     1888:	0f 01 cb             	stac
188b     188b:	0f ae e8             	lfence
188e     188e:	0f 01 ca             	clac
1891     1891:	0f 01 ca             	clac
1894     1894:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
189e     189e:	0f 01 cb             	stac
18a1     18a1:	0f ae e8             	lfence
18a4     18a4:	0f 01 ca             	clac
18a7     18a7:	0f 01 ca             	clac
18aa     18aa:	9c                   	pushf
18ab     18ab:	58                   	pop    %rax
18ac     18ac:	fa                   	cli
18ad     18ad:	fb                   	sti
18ae     18ae:	9c                   	pushf
18af     18af:	58                   	pop    %rax
18b0     18b0:	fa                   	cli
18b1     18b1:	9c                   	pushf
18b2     18b2:	58                   	pop    %rax
18b3     18b3:	fa                   	cli
18b4     18b4:	9c                   	pushf
18b5     18b5:	58                   	pop    %rax
18b6     18b6:	fb                   	sti
18b7     18b7:	fb                   	sti
18b8     18b8:	9c                   	pushf
18b9     18b9:	58                   	pop    %rax
18ba     18ba:	fa                   	cli
18bb     18bb:	9c                   	pushf
18bc     18bc:	58                   	pop    %rax
18bd     18bd:	fa                   	cli
18be     18be:	fb                   	sti
18bf     18bf:	fb                   	sti
18c0     18c0:	9c                   	pushf
18c1     18c1:	58                   	pop    %rax
18c2     18c2:	fa                   	cli
18c3     18c3:	9c                   	pushf
18c4     18c4:	58                   	pop    %rax
18c5     18c5:	fb                   	sti
18c6     18c6:	9c                   	pushf
18c7     18c7:	58                   	pop    %rax
18c8     18c8:	fa                   	cli
18c9     18c9:	fb                   	sti
18ca     18ca:	9c                   	pushf
18cb     18cb:	58                   	pop    %rax
18cc     18cc:	fa                   	cli
18cd     18cd:	fb                   	sti
18ce     18ce:	9c                   	pushf
18cf     18cf:	58                   	pop    %rax
18d0     18d0:	fa                   	cli
18d1     18d1:	9c                   	pushf
18d2     18d2:	58                   	pop    %rax
18d3     18d3:	fa                   	cli
18d4     18d4:	9c                   	pushf
18d5     18d5:	58                   	pop    %rax
18d6     18d6:	fb                   	sti
18d7     18d7:	9c                   	pushf
18d8     18d8:	58                   	pop    %rax
18d9     18d9:	fa                   	cli
18da     18da:	9c                   	pushf
18db     18db:	58                   	pop    %rax
18dc     18dc:	fb                   	sti
18dd     18dd:	9c                   	pushf
18de     18de:	58                   	pop    %rax
18df     18df:	fa                   	cli
18e0     18e0:	fb                   	sti
18e1     18e1:	e9 00 00 00 00       	jmp    18e6 <.altinstr_replacement+0x18e6>	18e2: R_X86_64_PC32	.text+0x45059a
18e6     18e6:	e9 00 00 00 00       	jmp    18eb <.altinstr_replacement+0x18eb>	18e7: R_X86_64_PC32	.text+0x4507e2
18eb     18eb:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
18f5     18f5:	49 bf 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r15
18ff     18ff:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
1909     1909:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
1913     1913:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
191d     191d:	49 be 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r14
1927     1927:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
1931     1931:	9c                   	pushf
1932     1932:	58                   	pop    %rax
1933     1933:	fa                   	cli
1934     1934:	9c                   	pushf
1935     1935:	58                   	pop    %rax
1936     1936:	fb                   	sti
1937     1937:	9c                   	pushf
1938     1938:	58                   	pop    %rax
1939     1939:	fa                   	cli
193a     193a:	9c                   	pushf
193b     193b:	58                   	pop    %rax
193c     193c:	fb                   	sti
193d     193d:	9c                   	pushf
193e     193e:	58                   	pop    %rax
193f     193f:	fa                   	cli
1940     1940:	fb                   	sti
1941     1941:	9c                   	pushf
1942     1942:	58                   	pop    %rax
1943     1943:	fa                   	cli
1944     1944:	9c                   	pushf
1945     1945:	58                   	pop    %rax
1946     1946:	fb                   	sti
1947     1947:	9c                   	pushf
1948     1948:	58                   	pop    %rax
1949     1949:	fa                   	cli
194a     194a:	fb                   	sti
194b     194b:	9c                   	pushf
194c     194c:	58                   	pop    %rax
194d     194d:	fa                   	cli
194e     194e:	9c                   	pushf
194f     194f:	58                   	pop    %rax
1950     1950:	fb                   	sti
1951     1951:	9c                   	pushf
1952     1952:	58                   	pop    %rax
1953     1953:	fb                   	sti
1954     1954:	9c                   	pushf
1955     1955:	58                   	pop    %rax
1956     1956:	fb                   	sti
1957     1957:	9c                   	pushf
1958     1958:	58                   	pop    %rax
1959     1959:	fb                   	sti
195a     195a:	9c                   	pushf
195b     195b:	58                   	pop    %rax
195c     195c:	9c                   	pushf
195d     195d:	58                   	pop    %rax
195e     195e:	9c                   	pushf
195f     195f:	58                   	pop    %rax
1960     1960:	fa                   	cli
1961     1961:	fb                   	sti
1962     1962:	9c                   	pushf
1963     1963:	58                   	pop    %rax
1964     1964:	fa                   	cli
1965     1965:	fb                   	sti
1966     1966:	9c                   	pushf
1967     1967:	58                   	pop    %rax
1968     1968:	fa                   	cli
1969     1969:	9c                   	pushf
196a     196a:	58                   	pop    %rax
196b     196b:	fb                   	sti
196c     196c:	e9 00 00 00 00       	jmp    1971 <.altinstr_replacement+0x1971>	196d: R_X86_64_PC32	.text+0x4c02c8
1971     1971:	e9 00 00 00 00       	jmp    1976 <.altinstr_replacement+0x1976>	1972: R_X86_64_PC32	.text+0x4c02d7
1976     1976:	9c                   	pushf
1977     1977:	58                   	pop    %rax
1978     1978:	9c                   	pushf
1979     1979:	58                   	pop    %rax
197a     197a:	9c                   	pushf
197b     197b:	58                   	pop    %rax
197c     197c:	9c                   	pushf
197d     197d:	58                   	pop    %rax
197e     197e:	9c                   	pushf
197f     197f:	58                   	pop    %rax
1980     1980:	9c                   	pushf
1981     1981:	58                   	pop    %rax
1982     1982:	9c                   	pushf
1983     1983:	58                   	pop    %rax
1984     1984:	9c                   	pushf
1985     1985:	58                   	pop    %rax
1986     1986:	9c                   	pushf
1987     1987:	58                   	pop    %rax
1988     1988:	fb                   	sti
1989     1989:	9c                   	pushf
198a     198a:	58                   	pop    %rax
198b     198b:	fa                   	cli
198c     198c:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
1996     1996:	9c                   	pushf
1997     1997:	58                   	pop    %rax
1998     1998:	fa                   	cli
1999     1999:	9c                   	pushf
199a     199a:	58                   	pop    %rax
199b     199b:	fa                   	cli
199c     199c:	9c                   	pushf
199d     199d:	58                   	pop    %rax
199e     199e:	fa                   	cli
199f     199f:	9c                   	pushf
19a0     19a0:	58                   	pop    %rax
19a1     19a1:	fb                   	sti
19a2     19a2:	fb                   	sti
19a3     19a3:	9c                   	pushf
19a4     19a4:	58                   	pop    %rax
19a5     19a5:	fa                   	cli
19a6     19a6:	fb                   	sti
19a7     19a7:	fb                   	sti
19a8     19a8:	9c                   	pushf
19a9     19a9:	58                   	pop    %rax
19aa     19aa:	9c                   	pushf
19ab     19ab:	58                   	pop    %rax
19ac     19ac:	9c                   	pushf
19ad     19ad:	58                   	pop    %rax
19ae     19ae:	fa                   	cli
19af     19af:	9c                   	pushf
19b0     19b0:	58                   	pop    %rax
19b1     19b1:	fb                   	sti
19b2     19b2:	fb                   	sti
19b3     19b3:	9c                   	pushf
19b4     19b4:	58                   	pop    %rax
19b5     19b5:	fa                   	cli
19b6     19b6:	9c                   	pushf
19b7     19b7:	58                   	pop    %rax
19b8     19b8:	fa                   	cli
19b9     19b9:	fb                   	sti
19ba     19ba:	fb                   	sti
19bb     19bb:	9c                   	pushf
19bc     19bc:	58                   	pop    %rax
19bd     19bd:	fb                   	sti
19be     19be:	9c                   	pushf
19bf     19bf:	58                   	pop    %rax
19c0     19c0:	fa                   	cli
19c1     19c1:	48 31 c0             	xor    %rax,%rax
19c4     19c4:	9c                   	pushf
19c5     19c5:	58                   	pop    %rax
19c6     19c6:	fa                   	cli
19c7     19c7:	9c                   	pushf
19c8     19c8:	58                   	pop    %rax
19c9     19c9:	fa                   	cli
19ca     19ca:	9c                   	pushf
19cb     19cb:	58                   	pop    %rax
19cc     19cc:	fb                   	sti
19cd     19cd:	9c                   	pushf
19ce     19ce:	58                   	pop    %rax
19cf     19cf:	fb                   	sti
19d0     19d0:	9c                   	pushf
19d1     19d1:	58                   	pop    %rax
19d2     19d2:	fb                   	sti
19d3     19d3:	fb                   	sti
19d4     19d4:	9c                   	pushf
19d5     19d5:	58                   	pop    %rax
19d6     19d6:	fa                   	cli
19d7     19d7:	fb                   	sti
19d8     19d8:	9c                   	pushf
19d9     19d9:	58                   	pop    %rax
19da     19da:	fa                   	cli
19db     19db:	9c                   	pushf
19dc     19dc:	58                   	pop    %rax
19dd     19dd:	fb                   	sti
19de     19de:	fb                   	sti
19df     19df:	fb                   	sti
19e0     19e0:	fb                   	sti
19e1     19e1:	fb                   	sti
19e2     19e2:	fa                   	cli
19e3     19e3:	fb                   	sti
19e4     19e4:	9c                   	pushf
19e5     19e5:	58                   	pop    %rax
19e6     19e6:	fb                   	sti
19e7     19e7:	9c                   	pushf
19e8     19e8:	58                   	pop    %rax
19e9     19e9:	fa                   	cli
19ea     19ea:	e9 00 00 00 00       	jmp    19ef <.altinstr_replacement+0x19ef>	19eb: R_X86_64_PC32	.text+0x526a57
19ef     19ef:	e9 00 00 00 00       	jmp    19f4 <.altinstr_replacement+0x19f4>	19f0: R_X86_64_PC32	.text+0x526a66
19f4     19f4:	9c                   	pushf
19f5     19f5:	58                   	pop    %rax
19f6     19f6:	fa                   	cli
19f7     19f7:	fb                   	sti
19f8     19f8:	9c                   	pushf
19f9     19f9:	58                   	pop    %rax
19fa     19fa:	fa                   	cli
19fb     19fb:	9c                   	pushf
19fc     19fc:	58                   	pop    %rax
19fd     19fd:	fb                   	sti
19fe     19fe:	9c                   	pushf
19ff     19ff:	58                   	pop    %rax
1a00     1a00:	fa                   	cli
1a01     1a01:	9c                   	pushf
1a02     1a02:	58                   	pop    %rax
1a03     1a03:	fb                   	sti
1a04     1a04:	9c                   	pushf
1a05     1a05:	58                   	pop    %rax
1a06     1a06:	fa                   	cli
1a07     1a07:	9c                   	pushf
1a08     1a08:	58                   	pop    %rax
1a09     1a09:	fa                   	cli
1a0a     1a0a:	9c                   	pushf
1a0b     1a0b:	58                   	pop    %rax
1a0c     1a0c:	fb                   	sti
1a0d     1a0d:	9c                   	pushf
1a0e     1a0e:	58                   	pop    %rax
1a0f     1a0f:	fa                   	cli
1a10     1a10:	fb                   	sti
1a11     1a11:	9c                   	pushf
1a12     1a12:	58                   	pop    %rax
1a13     1a13:	fa                   	cli
1a14     1a14:	9c                   	pushf
1a15     1a15:	58                   	pop    %rax
1a16     1a16:	fb                   	sti
1a17     1a17:	9c                   	pushf
1a18     1a18:	58                   	pop    %rax
1a19     1a19:	fa                   	cli
1a1a     1a1a:	fb                   	sti
1a1b     1a1b:	fb                   	sti
1a1c     1a1c:	fb                   	sti
1a1d     1a1d:	48 31 c0             	xor    %rax,%rax
1a20     1a20:	48 31 c0             	xor    %rax,%rax
1a23     1a23:	48 31 c0             	xor    %rax,%rax
1a26     1a26:	48 31 c0             	xor    %rax,%rax
1a29     1a29:	9c                   	pushf
1a2a     1a2a:	58                   	pop    %rax
1a2b     1a2b:	9c                   	pushf
1a2c     1a2c:	58                   	pop    %rax
1a2d     1a2d:	9c                   	pushf
1a2e     1a2e:	58                   	pop    %rax
1a2f     1a2f:	9c                   	pushf
1a30     1a30:	58                   	pop    %rax
1a31     1a31:	9c                   	pushf
1a32     1a32:	58                   	pop    %rax
1a33     1a33:	9c                   	pushf
1a34     1a34:	58                   	pop    %rax
1a35     1a35:	9c                   	pushf
1a36     1a36:	58                   	pop    %rax
1a37     1a37:	9c                   	pushf
1a38     1a38:	58                   	pop    %rax
1a39     1a39:	c6 07 00             	movb   $0x0,(%rdi)
1a3c     1a3c:	9c                   	pushf
1a3d     1a3d:	58                   	pop    %rax
1a3e     1a3e:	9c                   	pushf
1a3f     1a3f:	58                   	pop    %rax
1a40     1a40:	fa                   	cli
1a41     1a41:	9c                   	pushf
1a42     1a42:	58                   	pop    %rax
1a43     1a43:	fb                   	sti
1a44     1a44:	9c                   	pushf
1a45     1a45:	58                   	pop    %rax
1a46     1a46:	9c                   	pushf
1a47     1a47:	58                   	pop    %rax
1a48     1a48:	9c                   	pushf
1a49     1a49:	58                   	pop    %rax
1a4a     1a4a:	9c                   	pushf
1a4b     1a4b:	58                   	pop    %rax
1a4c     1a4c:	fa                   	cli
1a4d     1a4d:	9c                   	pushf
1a4e     1a4e:	58                   	pop    %rax
1a4f     1a4f:	fb                   	sti
1a50     1a50:	9c                   	pushf
1a51     1a51:	58                   	pop    %rax
1a52     1a52:	fa                   	cli
1a53     1a53:	9c                   	pushf
1a54     1a54:	58                   	pop    %rax
1a55     1a55:	fb                   	sti
1a56     1a56:	9c                   	pushf
1a57     1a57:	58                   	pop    %rax
1a58     1a58:	fa                   	cli
1a59     1a59:	9c                   	pushf
1a5a     1a5a:	58                   	pop    %rax
1a5b     1a5b:	fb                   	sti
1a5c     1a5c:	9c                   	pushf
1a5d     1a5d:	58                   	pop    %rax
1a5e     1a5e:	fa                   	cli
1a5f     1a5f:	9c                   	pushf
1a60     1a60:	58                   	pop    %rax
1a61     1a61:	fb                   	sti
1a62     1a62:	9c                   	pushf
1a63     1a63:	58                   	pop    %rax
1a64     1a64:	fa                   	cli
1a65     1a65:	9c                   	pushf
1a66     1a66:	58                   	pop    %rax
1a67     1a67:	fb                   	sti
1a68     1a68:	9c                   	pushf
1a69     1a69:	58                   	pop    %rax
1a6a     1a6a:	fa                   	cli
1a6b     1a6b:	9c                   	pushf
1a6c     1a6c:	58                   	pop    %rax
1a6d     1a6d:	fb                   	sti
1a6e     1a6e:	9c                   	pushf
1a6f     1a6f:	58                   	pop    %rax
1a70     1a70:	fa                   	cli
1a71     1a71:	9c                   	pushf
1a72     1a72:	58                   	pop    %rax
1a73     1a73:	fb                   	sti
1a74     1a74:	9c                   	pushf
1a75     1a75:	58                   	pop    %rax
1a76     1a76:	9c                   	pushf
1a77     1a77:	58                   	pop    %rax
1a78     1a78:	fa                   	cli
1a79     1a79:	9c                   	pushf
1a7a     1a7a:	58                   	pop    %rax
1a7b     1a7b:	fb                   	sti
1a7c     1a7c:	9c                   	pushf
1a7d     1a7d:	58                   	pop    %rax
1a7e     1a7e:	fa                   	cli
1a7f     1a7f:	9c                   	pushf
1a80     1a80:	58                   	pop    %rax
1a81     1a81:	fb                   	sti
1a82     1a82:	9c                   	pushf
1a83     1a83:	58                   	pop    %rax
1a84     1a84:	9c                   	pushf
1a85     1a85:	58                   	pop    %rax
1a86     1a86:	9c                   	pushf
1a87     1a87:	58                   	pop    %rax
1a88     1a88:	fa                   	cli
1a89     1a89:	9c                   	pushf
1a8a     1a8a:	58                   	pop    %rax
1a8b     1a8b:	fb                   	sti
1a8c     1a8c:	9c                   	pushf
1a8d     1a8d:	58                   	pop    %rax
1a8e     1a8e:	9c                   	pushf
1a8f     1a8f:	58                   	pop    %rax
1a90     1a90:	9c                   	pushf
1a91     1a91:	58                   	pop    %rax
1a92     1a92:	9c                   	pushf
1a93     1a93:	58                   	pop    %rax
1a94     1a94:	fa                   	cli
1a95     1a95:	9c                   	pushf
1a96     1a96:	58                   	pop    %rax
1a97     1a97:	fb                   	sti
1a98     1a98:	9c                   	pushf
1a99     1a99:	58                   	pop    %rax
1a9a     1a9a:	fa                   	cli
1a9b     1a9b:	9c                   	pushf
1a9c     1a9c:	58                   	pop    %rax
1a9d     1a9d:	fb                   	sti
1a9e     1a9e:	9c                   	pushf
1a9f     1a9f:	58                   	pop    %rax
1aa0     1aa0:	fa                   	cli
1aa1     1aa1:	9c                   	pushf
1aa2     1aa2:	58                   	pop    %rax
1aa3     1aa3:	fb                   	sti
1aa4     1aa4:	9c                   	pushf
1aa5     1aa5:	58                   	pop    %rax
1aa6     1aa6:	fa                   	cli
1aa7     1aa7:	9c                   	pushf
1aa8     1aa8:	58                   	pop    %rax
1aa9     1aa9:	fb                   	sti
1aaa     1aaa:	9c                   	pushf
1aab     1aab:	58                   	pop    %rax
1aac     1aac:	fa                   	cli
1aad     1aad:	9c                   	pushf
1aae     1aae:	58                   	pop    %rax
1aaf     1aaf:	fb                   	sti
1ab0     1ab0:	9c                   	pushf
1ab1     1ab1:	58                   	pop    %rax
1ab2     1ab2:	fa                   	cli
1ab3     1ab3:	9c                   	pushf
1ab4     1ab4:	58                   	pop    %rax
1ab5     1ab5:	fb                   	sti
1ab6     1ab6:	9c                   	pushf
1ab7     1ab7:	58                   	pop    %rax
1ab8     1ab8:	fa                   	cli
1ab9     1ab9:	9c                   	pushf
1aba     1aba:	58                   	pop    %rax
1abb     1abb:	fb                   	sti
1abc     1abc:	9c                   	pushf
1abd     1abd:	58                   	pop    %rax
1abe     1abe:	fa                   	cli
1abf     1abf:	9c                   	pushf
1ac0     1ac0:	58                   	pop    %rax
1ac1     1ac1:	fb                   	sti
1ac2     1ac2:	9c                   	pushf
1ac3     1ac3:	58                   	pop    %rax
1ac4     1ac4:	fa                   	cli
1ac5     1ac5:	9c                   	pushf
1ac6     1ac6:	58                   	pop    %rax
1ac7     1ac7:	fb                   	sti
1ac8     1ac8:	9c                   	pushf
1ac9     1ac9:	58                   	pop    %rax
1aca     1aca:	fa                   	cli
1acb     1acb:	9c                   	pushf
1acc     1acc:	58                   	pop    %rax
1acd     1acd:	fb                   	sti
1ace     1ace:	9c                   	pushf
1acf     1acf:	58                   	pop    %rax
1ad0     1ad0:	9c                   	pushf
1ad1     1ad1:	58                   	pop    %rax
1ad2     1ad2:	9c                   	pushf
1ad3     1ad3:	58                   	pop    %rax
1ad4     1ad4:	9c                   	pushf
1ad5     1ad5:	58                   	pop    %rax
1ad6     1ad6:	9c                   	pushf
1ad7     1ad7:	58                   	pop    %rax
1ad8     1ad8:	9c                   	pushf
1ad9     1ad9:	58                   	pop    %rax
1ada     1ada:	9c                   	pushf
1adb     1adb:	58                   	pop    %rax
1adc     1adc:	fa                   	cli
1add     1add:	9c                   	pushf
1ade     1ade:	58                   	pop    %rax
1adf     1adf:	fb                   	sti
1ae0     1ae0:	9c                   	pushf
1ae1     1ae1:	58                   	pop    %rax
1ae2     1ae2:	fa                   	cli
1ae3     1ae3:	9c                   	pushf
1ae4     1ae4:	58                   	pop    %rax
1ae5     1ae5:	fa                   	cli
1ae6     1ae6:	9c                   	pushf
1ae7     1ae7:	58                   	pop    %rax
1ae8     1ae8:	fa                   	cli
1ae9     1ae9:	fb                   	sti
1aea     1aea:	9c                   	pushf
1aeb     1aeb:	58                   	pop    %rax
1aec     1aec:	fb                   	sti
1aed     1aed:	9c                   	pushf
1aee     1aee:	58                   	pop    %rax
1aef     1aef:	fa                   	cli
1af0     1af0:	9c                   	pushf
1af1     1af1:	58                   	pop    %rax
1af2     1af2:	fa                   	cli
1af3     1af3:	9c                   	pushf
1af4     1af4:	58                   	pop    %rax
1af5     1af5:	fa                   	cli
1af6     1af6:	9c                   	pushf
1af7     1af7:	58                   	pop    %rax
1af8     1af8:	fa                   	cli
1af9     1af9:	fb                   	sti
1afa     1afa:	9c                   	pushf
1afb     1afb:	58                   	pop    %rax
1afc     1afc:	fb                   	sti
1afd     1afd:	fb                   	sti
1afe     1afe:	9c                   	pushf
1aff     1aff:	58                   	pop    %rax
1b00     1b00:	fb                   	sti
1b01     1b01:	48 31 c0             	xor    %rax,%rax
1b04     1b04:	41 0f 0d 0e          	prefetchw (%r14)
1b08     1b08:	41 0f 0d 4d 00       	prefetchw 0x0(%r13)
1b0d     1b0d:	48 31 c0             	xor    %rax,%rax
1b10     1b10:	c6 07 00             	movb   $0x0,(%rdi)
1b13     1b13:	c6 07 00             	movb   $0x0,(%rdi)
1b16     1b16:	c6 07 00             	movb   $0x0,(%rdi)
1b19     1b19:	9c                   	pushf
1b1a     1b1a:	58                   	pop    %rax
1b1b     1b1b:	fa                   	cli
1b1c     1b1c:	fb                   	sti
1b1d     1b1d:	9c                   	pushf
1b1e     1b1e:	58                   	pop    %rax
1b1f     1b1f:	9c                   	pushf
1b20     1b20:	58                   	pop    %rax
1b21     1b21:	9c                   	pushf
1b22     1b22:	58                   	pop    %rax
1b23     1b23:	fa                   	cli
1b24     1b24:	fb                   	sti
1b25     1b25:	9c                   	pushf
1b26     1b26:	58                   	pop    %rax
1b27     1b27:	fa                   	cli
1b28     1b28:	fb                   	sti
1b29     1b29:	9c                   	pushf
1b2a     1b2a:	58                   	pop    %rax
1b2b     1b2b:	fa                   	cli
1b2c     1b2c:	fb                   	sti
1b2d     1b2d:	e9 00 00 00 00       	jmp    1b32 <.altinstr_replacement+0x1b32>	1b2e: R_X86_64_PC32	.text.unlikely+0x43bc2
1b32     1b32:	e9 00 00 00 00       	jmp    1b37 <.altinstr_replacement+0x1b37>	1b33: R_X86_64_PC32	.text.unlikely+0x43c06
1b37     1b37:	e9 00 00 00 00       	jmp    1b3c <.altinstr_replacement+0x1b3c>	1b38: R_X86_64_PC32	.text+0x570429
1b3c     1b3c:	e9 00 00 00 00       	jmp    1b41 <.altinstr_replacement+0x1b41>	1b3d: R_X86_64_PC32	.text+0x570434
1b41     1b41:	e9 00 00 00 00       	jmp    1b46 <.altinstr_replacement+0x1b46>	1b42: R_X86_64_PC32	.text+0x5707dc
1b46     1b46:	e9 00 00 00 00       	jmp    1b4b <.altinstr_replacement+0x1b4b>	1b47: R_X86_64_PC32	.text+0x5707fb
1b4b     1b4b:	e8 00 00 00 00       	call   1b50 <.altinstr_replacement+0x1b50>	1b4c: R_X86_64_PLT32	clear_page_rep-0x4
1b50     1b50:	e8 00 00 00 00       	call   1b55 <.altinstr_replacement+0x1b55>	1b51: R_X86_64_PLT32	clear_page_erms-0x4
1b55     1b55:	e9 00 00 00 00       	jmp    1b5a <.altinstr_replacement+0x1b5a>	1b56: R_X86_64_PC32	.text+0x570c76
1b5a     1b5a:	e9 00 00 00 00       	jmp    1b5f <.altinstr_replacement+0x1b5f>	1b5b: R_X86_64_PC32	.text+0x570c81
1b5f     1b5f:	e8 00 00 00 00       	call   1b64 <.altinstr_replacement+0x1b64>	1b60: R_X86_64_PLT32	clear_page_rep-0x4
1b64     1b64:	e8 00 00 00 00       	call   1b69 <.altinstr_replacement+0x1b69>	1b65: R_X86_64_PLT32	clear_page_erms-0x4
1b69     1b69:	e9 00 00 00 00       	jmp    1b6e <.altinstr_replacement+0x1b6e>	1b6a: R_X86_64_PC32	.text+0x571aa5
1b6e     1b6e:	e9 00 00 00 00       	jmp    1b73 <.altinstr_replacement+0x1b73>	1b6f: R_X86_64_PC32	.text+0x571ab0
1b73     1b73:	e8 00 00 00 00       	call   1b78 <.altinstr_replacement+0x1b78>	1b74: R_X86_64_PLT32	clear_page_rep-0x4
1b78     1b78:	e8 00 00 00 00       	call   1b7d <.altinstr_replacement+0x1b7d>	1b79: R_X86_64_PLT32	clear_page_erms-0x4
1b7d     1b7d:	e8 00 00 00 00       	call   1b82 <.altinstr_replacement+0x1b82>	1b7e: R_X86_64_PLT32	clear_page_rep-0x4
1b82     1b82:	e8 00 00 00 00       	call   1b87 <.altinstr_replacement+0x1b87>	1b83: R_X86_64_PLT32	clear_page_erms-0x4
1b87     1b87:	9c                   	pushf
1b88     1b88:	58                   	pop    %rax
1b89     1b89:	fa                   	cli
1b8a     1b8a:	9c                   	pushf
1b8b     1b8b:	58                   	pop    %rax
1b8c     1b8c:	fb                   	sti
1b8d     1b8d:	9c                   	pushf
1b8e     1b8e:	58                   	pop    %rax
1b8f     1b8f:	fa                   	cli
1b90     1b90:	9c                   	pushf
1b91     1b91:	58                   	pop    %rax
1b92     1b92:	fb                   	sti
1b93     1b93:	9c                   	pushf
1b94     1b94:	58                   	pop    %rax
1b95     1b95:	fa                   	cli
1b96     1b96:	9c                   	pushf
1b97     1b97:	58                   	pop    %rax
1b98     1b98:	fb                   	sti
1b99     1b99:	9c                   	pushf
1b9a     1b9a:	58                   	pop    %rax
1b9b     1b9b:	fa                   	cli
1b9c     1b9c:	9c                   	pushf
1b9d     1b9d:	58                   	pop    %rax
1b9e     1b9e:	fb                   	sti
1b9f     1b9f:	9c                   	pushf
1ba0     1ba0:	58                   	pop    %rax
1ba1     1ba1:	fb                   	sti
1ba2     1ba2:	9c                   	pushf
1ba3     1ba3:	58                   	pop    %rax
1ba4     1ba4:	fa                   	cli
1ba5     1ba5:	9c                   	pushf
1ba6     1ba6:	58                   	pop    %rax
1ba7     1ba7:	fb                   	sti
1ba8     1ba8:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
1bb2     1bb2:	49 be 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r14
1bbc     1bbc:	9c                   	pushf
1bbd     1bbd:	58                   	pop    %rax
1bbe     1bbe:	fa                   	cli
1bbf     1bbf:	9c                   	pushf
1bc0     1bc0:	58                   	pop    %rax
1bc1     1bc1:	fb                   	sti
1bc2     1bc2:	9c                   	pushf
1bc3     1bc3:	58                   	pop    %rax
1bc4     1bc4:	fb                   	sti
1bc5     1bc5:	9c                   	pushf
1bc6     1bc6:	58                   	pop    %rax
1bc7     1bc7:	fb                   	sti
1bc8     1bc8:	9c                   	pushf
1bc9     1bc9:	58                   	pop    %rax
1bca     1bca:	fa                   	cli
1bcb     1bcb:	9c                   	pushf
1bcc     1bcc:	58                   	pop    %rax
1bcd     1bcd:	fb                   	sti
1bce     1bce:	9c                   	pushf
1bcf     1bcf:	58                   	pop    %rax
1bd0     1bd0:	fa                   	cli
1bd1     1bd1:	9c                   	pushf
1bd2     1bd2:	58                   	pop    %rax
1bd3     1bd3:	fb                   	sti
1bd4     1bd4:	9c                   	pushf
1bd5     1bd5:	58                   	pop    %rax
1bd6     1bd6:	fa                   	cli
1bd7     1bd7:	9c                   	pushf
1bd8     1bd8:	58                   	pop    %rax
1bd9     1bd9:	fb                   	sti
1bda     1bda:	9c                   	pushf
1bdb     1bdb:	58                   	pop    %rax
1bdc     1bdc:	9c                   	pushf
1bdd     1bdd:	58                   	pop    %rax
1bde     1bde:	fa                   	cli
1bdf     1bdf:	9c                   	pushf
1be0     1be0:	58                   	pop    %rax
1be1     1be1:	fa                   	cli
1be2     1be2:	fb                   	sti
1be3     1be3:	9c                   	pushf
1be4     1be4:	58                   	pop    %rax
1be5     1be5:	9c                   	pushf
1be6     1be6:	58                   	pop    %rax
1be7     1be7:	9c                   	pushf
1be8     1be8:	58                   	pop    %rax
1be9     1be9:	fa                   	cli
1bea     1bea:	9c                   	pushf
1beb     1beb:	58                   	pop    %rax
1bec     1bec:	fb                   	sti
1bed     1bed:	fb                   	sti
1bee     1bee:	9c                   	pushf
1bef     1bef:	58                   	pop    %rax
1bf0     1bf0:	fa                   	cli
1bf1     1bf1:	9c                   	pushf
1bf2     1bf2:	58                   	pop    %rax
1bf3     1bf3:	fa                   	cli
1bf4     1bf4:	fb                   	sti
1bf5     1bf5:	9c                   	pushf
1bf6     1bf6:	58                   	pop    %rax
1bf7     1bf7:	9c                   	pushf
1bf8     1bf8:	58                   	pop    %rax
1bf9     1bf9:	fa                   	cli
1bfa     1bfa:	9c                   	pushf
1bfb     1bfb:	58                   	pop    %rax
1bfc     1bfc:	9c                   	pushf
1bfd     1bfd:	58                   	pop    %rax
1bfe     1bfe:	9c                   	pushf
1bff     1bff:	58                   	pop    %rax
1c00     1c00:	fa                   	cli
1c01     1c01:	9c                   	pushf
1c02     1c02:	58                   	pop    %rax
1c03     1c03:	fa                   	cli
1c04     1c04:	9c                   	pushf
1c05     1c05:	58                   	pop    %rax
1c06     1c06:	fb                   	sti
1c07     1c07:	9c                   	pushf
1c08     1c08:	58                   	pop    %rax
1c09     1c09:	fa                   	cli
1c0a     1c0a:	9c                   	pushf
1c0b     1c0b:	58                   	pop    %rax
1c0c     1c0c:	fb                   	sti
1c0d     1c0d:	9c                   	pushf
1c0e     1c0e:	58                   	pop    %rax
1c0f     1c0f:	fa                   	cli
1c10     1c10:	fb                   	sti
1c11     1c11:	9c                   	pushf
1c12     1c12:	58                   	pop    %rax
1c13     1c13:	fa                   	cli
1c14     1c14:	fb                   	sti
1c15     1c15:	9c                   	pushf
1c16     1c16:	58                   	pop    %rax
1c17     1c17:	fa                   	cli
1c18     1c18:	fb                   	sti
1c19     1c19:	9c                   	pushf
1c1a     1c1a:	58                   	pop    %rax
1c1b     1c1b:	fa                   	cli
1c1c     1c1c:	9c                   	pushf
1c1d     1c1d:	58                   	pop    %rax
1c1e     1c1e:	fb                   	sti
1c1f     1c1f:	9c                   	pushf
1c20     1c20:	58                   	pop    %rax
1c21     1c21:	fa                   	cli
1c22     1c22:	9c                   	pushf
1c23     1c23:	58                   	pop    %rax
1c24     1c24:	fb                   	sti
1c25     1c25:	9c                   	pushf
1c26     1c26:	58                   	pop    %rax
1c27     1c27:	fa                   	cli
1c28     1c28:	9c                   	pushf
1c29     1c29:	58                   	pop    %rax
1c2a     1c2a:	fa                   	cli
1c2b     1c2b:	9c                   	pushf
1c2c     1c2c:	58                   	pop    %rax
1c2d     1c2d:	fb                   	sti
1c2e     1c2e:	9c                   	pushf
1c2f     1c2f:	58                   	pop    %rax
1c30     1c30:	9c                   	pushf
1c31     1c31:	58                   	pop    %rax
1c32     1c32:	fb                   	sti
1c33     1c33:	9c                   	pushf
1c34     1c34:	58                   	pop    %rax
1c35     1c35:	fa                   	cli
1c36     1c36:	9c                   	pushf
1c37     1c37:	58                   	pop    %rax
1c38     1c38:	fa                   	cli
1c39     1c39:	9c                   	pushf
1c3a     1c3a:	58                   	pop    %rax
1c3b     1c3b:	9c                   	pushf
1c3c     1c3c:	58                   	pop    %rax
1c3d     1c3d:	9c                   	pushf
1c3e     1c3e:	58                   	pop    %rax
1c3f     1c3f:	fb                   	sti
1c40     1c40:	9c                   	pushf
1c41     1c41:	58                   	pop    %rax
1c42     1c42:	9c                   	pushf
1c43     1c43:	58                   	pop    %rax
1c44     1c44:	fa                   	cli
1c45     1c45:	9c                   	pushf
1c46     1c46:	58                   	pop    %rax
1c47     1c47:	fa                   	cli
1c48     1c48:	9c                   	pushf
1c49     1c49:	58                   	pop    %rax
1c4a     1c4a:	fb                   	sti
1c4b     1c4b:	9c                   	pushf
1c4c     1c4c:	58                   	pop    %rax
1c4d     1c4d:	fa                   	cli
1c4e     1c4e:	9c                   	pushf
1c4f     1c4f:	58                   	pop    %rax
1c50     1c50:	fa                   	cli
1c51     1c51:	9c                   	pushf
1c52     1c52:	58                   	pop    %rax
1c53     1c53:	fa                   	cli
1c54     1c54:	9c                   	pushf
1c55     1c55:	58                   	pop    %rax
1c56     1c56:	fa                   	cli
1c57     1c57:	9c                   	pushf
1c58     1c58:	58                   	pop    %rax
1c59     1c59:	fa                   	cli
1c5a     1c5a:	9c                   	pushf
1c5b     1c5b:	58                   	pop    %rax
1c5c     1c5c:	fa                   	cli
1c5d     1c5d:	9c                   	pushf
1c5e     1c5e:	58                   	pop    %rax
1c5f     1c5f:	fa                   	cli
1c60     1c60:	9c                   	pushf
1c61     1c61:	58                   	pop    %rax
1c62     1c62:	fb                   	sti
1c63     1c63:	9c                   	pushf
1c64     1c64:	58                   	pop    %rax
1c65     1c65:	fa                   	cli
1c66     1c66:	9c                   	pushf
1c67     1c67:	58                   	pop    %rax
1c68     1c68:	fa                   	cli
1c69     1c69:	c6 07 00             	movb   $0x0,(%rdi)
1c6c     1c6c:	9c                   	pushf
1c6d     1c6d:	58                   	pop    %rax
1c6e     1c6e:	fb                   	sti
1c6f     1c6f:	c6 07 00             	movb   $0x0,(%rdi)
1c72     1c72:	9c                   	pushf
1c73     1c73:	58                   	pop    %rax
1c74     1c74:	9c                   	pushf
1c75     1c75:	58                   	pop    %rax
1c76     1c76:	fa                   	cli
1c77     1c77:	9c                   	pushf
1c78     1c78:	58                   	pop    %rax
1c79     1c79:	fb                   	sti
1c7a     1c7a:	9c                   	pushf
1c7b     1c7b:	58                   	pop    %rax
1c7c     1c7c:	fa                   	cli
1c7d     1c7d:	9c                   	pushf
1c7e     1c7e:	58                   	pop    %rax
1c7f     1c7f:	fb                   	sti
1c80     1c80:	9c                   	pushf
1c81     1c81:	58                   	pop    %rax
1c82     1c82:	fa                   	cli
1c83     1c83:	c6 07 00             	movb   $0x0,(%rdi)
1c86     1c86:	9c                   	pushf
1c87     1c87:	58                   	pop    %rax
1c88     1c88:	fb                   	sti
1c89     1c89:	9c                   	pushf
1c8a     1c8a:	58                   	pop    %rax
1c8b     1c8b:	fa                   	cli
1c8c     1c8c:	9c                   	pushf
1c8d     1c8d:	58                   	pop    %rax
1c8e     1c8e:	fa                   	cli
1c8f     1c8f:	9c                   	pushf
1c90     1c90:	58                   	pop    %rax
1c91     1c91:	fa                   	cli
1c92     1c92:	9c                   	pushf
1c93     1c93:	58                   	pop    %rax
1c94     1c94:	fb                   	sti
1c95     1c95:	9c                   	pushf
1c96     1c96:	58                   	pop    %rax
1c97     1c97:	fa                   	cli
1c98     1c98:	9c                   	pushf
1c99     1c99:	58                   	pop    %rax
1c9a     1c9a:	fa                   	cli
1c9b     1c9b:	c6 07 00             	movb   $0x0,(%rdi)
1c9e     1c9e:	9c                   	pushf
1c9f     1c9f:	58                   	pop    %rax
1ca0     1ca0:	fb                   	sti
1ca1     1ca1:	9c                   	pushf
1ca2     1ca2:	58                   	pop    %rax
1ca3     1ca3:	fa                   	cli
1ca4     1ca4:	9c                   	pushf
1ca5     1ca5:	58                   	pop    %rax
1ca6     1ca6:	fa                   	cli
1ca7     1ca7:	fb                   	sti
1ca8     1ca8:	9c                   	pushf
1ca9     1ca9:	58                   	pop    %rax
1caa     1caa:	9c                   	pushf
1cab     1cab:	58                   	pop    %rax
1cac     1cac:	fa                   	cli
1cad     1cad:	9c                   	pushf
1cae     1cae:	58                   	pop    %rax
1caf     1caf:	fb                   	sti
1cb0     1cb0:	fb                   	sti
1cb1     1cb1:	fb                   	sti
1cb2     1cb2:	fb                   	sti
1cb3     1cb3:	48 be 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rsi
1cbd     1cbd:	e9 00 00 00 00       	jmp    1cc2 <.altinstr_replacement+0x1cc2>	1cbe: R_X86_64_PC32	.text+0x61012d
1cc2     1cc2:	9c                   	pushf
1cc3     1cc3:	58                   	pop    %rax
1cc4     1cc4:	fa                   	cli
1cc5     1cc5:	9c                   	pushf
1cc6     1cc6:	58                   	pop    %rax
1cc7     1cc7:	fb                   	sti
1cc8     1cc8:	9c                   	pushf
1cc9     1cc9:	58                   	pop    %rax
1cca     1cca:	fa                   	cli
1ccb     1ccb:	9c                   	pushf
1ccc     1ccc:	58                   	pop    %rax
1ccd     1ccd:	fb                   	sti
1cce     1cce:	9c                   	pushf
1ccf     1ccf:	58                   	pop    %rax
1cd0     1cd0:	fa                   	cli
1cd1     1cd1:	fb                   	sti
1cd2     1cd2:	9c                   	pushf
1cd3     1cd3:	58                   	pop    %rax
1cd4     1cd4:	fa                   	cli
1cd5     1cd5:	9c                   	pushf
1cd6     1cd6:	58                   	pop    %rax
1cd7     1cd7:	fb                   	sti
1cd8     1cd8:	9c                   	pushf
1cd9     1cd9:	58                   	pop    %rax
1cda     1cda:	fa                   	cli
1cdb     1cdb:	fb                   	sti
1cdc     1cdc:	9c                   	pushf
1cdd     1cdd:	58                   	pop    %rax
1cde     1cde:	fa                   	cli
1cdf     1cdf:	9c                   	pushf
1ce0     1ce0:	58                   	pop    %rax
1ce1     1ce1:	fb                   	sti
1ce2     1ce2:	9c                   	pushf
1ce3     1ce3:	58                   	pop    %rax
1ce4     1ce4:	fa                   	cli
1ce5     1ce5:	9c                   	pushf
1ce6     1ce6:	58                   	pop    %rax
1ce7     1ce7:	fb                   	sti
1ce8     1ce8:	9c                   	pushf
1ce9     1ce9:	58                   	pop    %rax
1cea     1cea:	fa                   	cli
1ceb     1ceb:	9c                   	pushf
1cec     1cec:	58                   	pop    %rax
1ced     1ced:	fb                   	sti
1cee     1cee:	9c                   	pushf
1cef     1cef:	58                   	pop    %rax
1cf0     1cf0:	fa                   	cli
1cf1     1cf1:	9c                   	pushf
1cf2     1cf2:	58                   	pop    %rax
1cf3     1cf3:	fb                   	sti
1cf4     1cf4:	9c                   	pushf
1cf5     1cf5:	58                   	pop    %rax
1cf6     1cf6:	fa                   	cli
1cf7     1cf7:	9c                   	pushf
1cf8     1cf8:	58                   	pop    %rax
1cf9     1cf9:	fb                   	sti
1cfa     1cfa:	9c                   	pushf
1cfb     1cfb:	58                   	pop    %rax
1cfc     1cfc:	fa                   	cli
1cfd     1cfd:	fb                   	sti
1cfe     1cfe:	9c                   	pushf
1cff     1cff:	58                   	pop    %rax
1d00     1d00:	fa                   	cli
1d01     1d01:	fb                   	sti
1d02     1d02:	49 be 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r14
1d0c     1d0c:	0f 01 cb             	stac
1d0f     1d0f:	0f ae e8             	lfence
1d12     1d12:	0f 01 ca             	clac
1d15     1d15:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
1d1f     1d1f:	49 bf 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r15
1d29     1d29:	0f 01 cb             	stac
1d2c     1d2c:	0f ae e8             	lfence
1d2f     1d2f:	0f 01 ca             	clac
1d32     1d32:	0f 01 ca             	clac
1d35     1d35:	0f 01 ca             	clac
1d38     1d38:	9c                   	pushf
1d39     1d39:	58                   	pop    %rax
1d3a     1d3a:	fa                   	cli
1d3b     1d3b:	9c                   	pushf
1d3c     1d3c:	58                   	pop    %rax
1d3d     1d3d:	fb                   	sti
1d3e     1d3e:	9c                   	pushf
1d3f     1d3f:	58                   	pop    %rax
1d40     1d40:	fa                   	cli
1d41     1d41:	9c                   	pushf
1d42     1d42:	58                   	pop    %rax
1d43     1d43:	fb                   	sti
1d44     1d44:	9c                   	pushf
1d45     1d45:	58                   	pop    %rax
1d46     1d46:	9c                   	pushf
1d47     1d47:	58                   	pop    %rax
1d48     1d48:	fa                   	cli
1d49     1d49:	9c                   	pushf
1d4a     1d4a:	58                   	pop    %rax
1d4b     1d4b:	fb                   	sti
1d4c     1d4c:	e9 00 00 00 00       	jmp    1d51 <.altinstr_replacement+0x1d51>	1d4d: R_X86_64_PC32	.init.text+0xb53cb
1d51     1d51:	e9 00 00 00 00       	jmp    1d56 <.altinstr_replacement+0x1d56>	1d52: R_X86_64_PC32	.init.text+0xb5473
1d56     1d56:	e9 00 00 00 00       	jmp    1d5b <.altinstr_replacement+0x1d5b>	1d57: R_X86_64_PC32	.text+0x67c20b
1d5b     1d5b:	e9 00 00 00 00       	jmp    1d60 <.altinstr_replacement+0x1d60>	1d5c: R_X86_64_PC32	.text+0x67ce42
1d60     1d60:	e8 00 00 00 00       	call   1d65 <.altinstr_replacement+0x1d65>	1d61: R_X86_64_PLT32	clear_page_rep-0x4
1d65     1d65:	e8 00 00 00 00       	call   1d6a <.altinstr_replacement+0x1d6a>	1d66: R_X86_64_PLT32	clear_page_erms-0x4
1d6a     1d6a:	e9 00 00 00 00       	jmp    1d6f <.altinstr_replacement+0x1d6f>	1d6b: R_X86_64_PC32	.text+0x67d99e
1d6f     1d6f:	e9 00 00 00 00       	jmp    1d74 <.altinstr_replacement+0x1d74>	1d70: R_X86_64_PC32	.text+0x67e554
1d74     1d74:	9c                   	pushf
1d75     1d75:	58                   	pop    %rax
1d76     1d76:	fa                   	cli
1d77     1d77:	fb                   	sti
1d78     1d78:	49 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r13
1d82     1d82:	49 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r13
1d8c     1d8c:	0f 01 cb             	stac
1d8f     1d8f:	0f ae e8             	lfence
1d92     1d92:	0f 01 ca             	clac
1d95     1d95:	0f 01 ca             	clac
1d98     1d98:	49 be 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r14
1da2     1da2:	0f 01 cb             	stac
1da5     1da5:	0f ae e8             	lfence
1da8     1da8:	0f 01 ca             	clac
1dab     1dab:	0f 01 ca             	clac
1dae     1dae:	9c                   	pushf
1daf     1daf:	58                   	pop    %rax
1db0     1db0:	fa                   	cli
1db1     1db1:	fb                   	sti
1db2     1db2:	9c                   	pushf
1db3     1db3:	58                   	pop    %rax
1db4     1db4:	9c                   	pushf
1db5     1db5:	58                   	pop    %rax
1db6     1db6:	fa                   	cli
1db7     1db7:	9c                   	pushf
1db8     1db8:	58                   	pop    %rax
1db9     1db9:	fb                   	sti
1dba     1dba:	9c                   	pushf
1dbb     1dbb:	58                   	pop    %rax
1dbc     1dbc:	fa                   	cli
1dbd     1dbd:	9c                   	pushf
1dbe     1dbe:	58                   	pop    %rax
1dbf     1dbf:	fb                   	sti
1dc0     1dc0:	9c                   	pushf
1dc1     1dc1:	58                   	pop    %rax
1dc2     1dc2:	fa                   	cli
1dc3     1dc3:	9c                   	pushf
1dc4     1dc4:	58                   	pop    %rax
1dc5     1dc5:	fb                   	sti
1dc6     1dc6:	9c                   	pushf
1dc7     1dc7:	58                   	pop    %rax
1dc8     1dc8:	fa                   	cli
1dc9     1dc9:	9c                   	pushf
1dca     1dca:	58                   	pop    %rax
1dcb     1dcb:	fb                   	sti
1dcc     1dcc:	9c                   	pushf
1dcd     1dcd:	58                   	pop    %rax
1dce     1dce:	fb                   	sti
1dcf     1dcf:	9c                   	pushf
1dd0     1dd0:	58                   	pop    %rax
1dd1     1dd1:	9c                   	pushf
1dd2     1dd2:	58                   	pop    %rax
1dd3     1dd3:	9c                   	pushf
1dd4     1dd4:	58                   	pop    %rax
1dd5     1dd5:	fa                   	cli
1dd6     1dd6:	9c                   	pushf
1dd7     1dd7:	58                   	pop    %rax
1dd8     1dd8:	9c                   	pushf
1dd9     1dd9:	58                   	pop    %rax
1dda     1dda:	9c                   	pushf
1ddb     1ddb:	58                   	pop    %rax
1ddc     1ddc:	fa                   	cli
1ddd     1ddd:	9c                   	pushf
1dde     1dde:	58                   	pop    %rax
1ddf     1ddf:	9c                   	pushf
1de0     1de0:	58                   	pop    %rax
1de1     1de1:	fb                   	sti
1de2     1de2:	9c                   	pushf
1de3     1de3:	58                   	pop    %rax
1de4     1de4:	fb                   	sti
1de5     1de5:	9c                   	pushf
1de6     1de6:	58                   	pop    %rax
1de7     1de7:	fa                   	cli
1de8     1de8:	9c                   	pushf
1de9     1de9:	58                   	pop    %rax
1dea     1dea:	fb                   	sti
1deb     1deb:	9c                   	pushf
1dec     1dec:	58                   	pop    %rax
1ded     1ded:	fa                   	cli
1dee     1dee:	9c                   	pushf
1def     1def:	58                   	pop    %rax
1df0     1df0:	fb                   	sti
1df1     1df1:	9c                   	pushf
1df2     1df2:	58                   	pop    %rax
1df3     1df3:	fb                   	sti
1df4     1df4:	9c                   	pushf
1df5     1df5:	58                   	pop    %rax
1df6     1df6:	fb                   	sti
1df7     1df7:	9c                   	pushf
1df8     1df8:	58                   	pop    %rax
1df9     1df9:	fa                   	cli
1dfa     1dfa:	9c                   	pushf
1dfb     1dfb:	58                   	pop    %rax
1dfc     1dfc:	fb                   	sti
1dfd     1dfd:	9c                   	pushf
1dfe     1dfe:	58                   	pop    %rax
1dff     1dff:	9c                   	pushf
1e00     1e00:	58                   	pop    %rax
1e01     1e01:	9c                   	pushf
1e02     1e02:	58                   	pop    %rax
1e03     1e03:	9c                   	pushf
1e04     1e04:	58                   	pop    %rax
1e05     1e05:	9c                   	pushf
1e06     1e06:	58                   	pop    %rax
1e07     1e07:	9c                   	pushf
1e08     1e08:	58                   	pop    %rax
1e09     1e09:	9c                   	pushf
1e0a     1e0a:	58                   	pop    %rax
1e0b     1e0b:	e9 00 00 00 00       	jmp    1e10 <.altinstr_replacement+0x1e10>	1e0c: R_X86_64_PC32	.text+0x717430
1e10     1e10:	e9 00 00 00 00       	jmp    1e15 <.altinstr_replacement+0x1e15>	1e11: R_X86_64_PC32	.text+0x717451
1e15     1e15:	9c                   	pushf
1e16     1e16:	58                   	pop    %rax
1e17     1e17:	fa                   	cli
1e18     1e18:	9c                   	pushf
1e19     1e19:	58                   	pop    %rax
1e1a     1e1a:	fb                   	sti
1e1b     1e1b:	9c                   	pushf
1e1c     1e1c:	58                   	pop    %rax
1e1d     1e1d:	fa                   	cli
1e1e     1e1e:	9c                   	pushf
1e1f     1e1f:	58                   	pop    %rax
1e20     1e20:	fb                   	sti
1e21     1e21:	9c                   	pushf
1e22     1e22:	58                   	pop    %rax
1e23     1e23:	fa                   	cli
1e24     1e24:	c6 07 00             	movb   $0x0,(%rdi)
1e27     1e27:	9c                   	pushf
1e28     1e28:	58                   	pop    %rax
1e29     1e29:	fb                   	sti
1e2a     1e2a:	9c                   	pushf
1e2b     1e2b:	58                   	pop    %rax
1e2c     1e2c:	fa                   	cli
1e2d     1e2d:	9c                   	pushf
1e2e     1e2e:	58                   	pop    %rax
1e2f     1e2f:	fb                   	sti
1e30     1e30:	9c                   	pushf
1e31     1e31:	58                   	pop    %rax
1e32     1e32:	fa                   	cli
1e33     1e33:	9c                   	pushf
1e34     1e34:	58                   	pop    %rax
1e35     1e35:	fb                   	sti
1e36     1e36:	9c                   	pushf
1e37     1e37:	58                   	pop    %rax
1e38     1e38:	fa                   	cli
1e39     1e39:	9c                   	pushf
1e3a     1e3a:	58                   	pop    %rax
1e3b     1e3b:	fb                   	sti
1e3c     1e3c:	9c                   	pushf
1e3d     1e3d:	58                   	pop    %rax
1e3e     1e3e:	9c                   	pushf
1e3f     1e3f:	58                   	pop    %rax
1e40     1e40:	fa                   	cli
1e41     1e41:	9c                   	pushf
1e42     1e42:	58                   	pop    %rax
1e43     1e43:	fb                   	sti
1e44     1e44:	9c                   	pushf
1e45     1e45:	58                   	pop    %rax
1e46     1e46:	fa                   	cli
1e47     1e47:	9c                   	pushf
1e48     1e48:	58                   	pop    %rax
1e49     1e49:	fb                   	sti
1e4a     1e4a:	9c                   	pushf
1e4b     1e4b:	58                   	pop    %rax
1e4c     1e4c:	fa                   	cli
1e4d     1e4d:	c6 07 00             	movb   $0x0,(%rdi)
1e50     1e50:	9c                   	pushf
1e51     1e51:	58                   	pop    %rax
1e52     1e52:	fb                   	sti
1e53     1e53:	9c                   	pushf
1e54     1e54:	58                   	pop    %rax
1e55     1e55:	fa                   	cli
1e56     1e56:	9c                   	pushf
1e57     1e57:	58                   	pop    %rax
1e58     1e58:	fb                   	sti
1e59     1e59:	c6 07 00             	movb   $0x0,(%rdi)
1e5c     1e5c:	c6 07 00             	movb   $0x0,(%rdi)
1e5f     1e5f:	9c                   	pushf
1e60     1e60:	58                   	pop    %rax
1e61     1e61:	fa                   	cli
1e62     1e62:	c6 07 00             	movb   $0x0,(%rdi)
1e65     1e65:	9c                   	pushf
1e66     1e66:	58                   	pop    %rax
1e67     1e67:	fb                   	sti
1e68     1e68:	9c                   	pushf
1e69     1e69:	58                   	pop    %rax
1e6a     1e6a:	fa                   	cli
1e6b     1e6b:	9c                   	pushf
1e6c     1e6c:	58                   	pop    %rax
1e6d     1e6d:	fb                   	sti
1e6e     1e6e:	9c                   	pushf
1e6f     1e6f:	58                   	pop    %rax
1e70     1e70:	fa                   	cli
1e71     1e71:	9c                   	pushf
1e72     1e72:	58                   	pop    %rax
1e73     1e73:	fb                   	sti
1e74     1e74:	9c                   	pushf
1e75     1e75:	58                   	pop    %rax
1e76     1e76:	fa                   	cli
1e77     1e77:	c6 07 00             	movb   $0x0,(%rdi)
1e7a     1e7a:	9c                   	pushf
1e7b     1e7b:	58                   	pop    %rax
1e7c     1e7c:	fb                   	sti
1e7d     1e7d:	c6 07 00             	movb   $0x0,(%rdi)
1e80     1e80:	c6 07 00             	movb   $0x0,(%rdi)
1e83     1e83:	c6 07 00             	movb   $0x0,(%rdi)
1e86     1e86:	c6 07 00             	movb   $0x0,(%rdi)
1e89     1e89:	c6 07 00             	movb   $0x0,(%rdi)
1e8c     1e8c:	c6 07 00             	movb   $0x0,(%rdi)
1e8f     1e8f:	c6 07 00             	movb   $0x0,(%rdi)
1e92     1e92:	9c                   	pushf
1e93     1e93:	58                   	pop    %rax
1e94     1e94:	fa                   	cli
1e95     1e95:	c6 07 00             	movb   $0x0,(%rdi)
1e98     1e98:	9c                   	pushf
1e99     1e99:	58                   	pop    %rax
1e9a     1e9a:	fb                   	sti
1e9b     1e9b:	c6 07 00             	movb   $0x0,(%rdi)
1e9e     1e9e:	c6 07 00             	movb   $0x0,(%rdi)
1ea1     1ea1:	c6 07 00             	movb   $0x0,(%rdi)
1ea4     1ea4:	9c                   	pushf
1ea5     1ea5:	58                   	pop    %rax
1ea6     1ea6:	c6 07 00             	movb   $0x0,(%rdi)
1ea9     1ea9:	9c                   	pushf
1eaa     1eaa:	58                   	pop    %rax
1eab     1eab:	9c                   	pushf
1eac     1eac:	58                   	pop    %rax
1ead     1ead:	e8 00 00 00 00       	call   1eb2 <.altinstr_replacement+0x1eb2>	1eae: R_X86_64_PLT32	copy_user_generic_string-0x4
1eb2     1eb2:	e8 00 00 00 00       	call   1eb7 <.altinstr_replacement+0x1eb7>	1eb3: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
1eb7     1eb7:	9c                   	pushf
1eb8     1eb8:	58                   	pop    %rax
1eb9     1eb9:	9c                   	pushf
1eba     1eba:	58                   	pop    %rax
1ebb     1ebb:	e8 00 00 00 00       	call   1ec0 <.altinstr_replacement+0x1ec0>	1ebc: R_X86_64_PLT32	copy_user_generic_string-0x4
1ec0     1ec0:	e8 00 00 00 00       	call   1ec5 <.altinstr_replacement+0x1ec5>	1ec1: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
1ec5     1ec5:	9c                   	pushf
1ec6     1ec6:	58                   	pop    %rax
1ec7     1ec7:	9c                   	pushf
1ec8     1ec8:	58                   	pop    %rax
1ec9     1ec9:	9c                   	pushf
1eca     1eca:	58                   	pop    %rax
1ecb     1ecb:	9c                   	pushf
1ecc     1ecc:	58                   	pop    %rax
1ecd     1ecd:	fa                   	cli
1ece     1ece:	9c                   	pushf
1ecf     1ecf:	58                   	pop    %rax
1ed0     1ed0:	fb                   	sti
1ed1     1ed1:	9c                   	pushf
1ed2     1ed2:	58                   	pop    %rax
1ed3     1ed3:	c6 07 00             	movb   $0x0,(%rdi)
1ed6     1ed6:	9c                   	pushf
1ed7     1ed7:	58                   	pop    %rax
1ed8     1ed8:	fa                   	cli
1ed9     1ed9:	c6 07 00             	movb   $0x0,(%rdi)
1edc     1edc:	fb                   	sti
1edd     1edd:	c6 07 00             	movb   $0x0,(%rdi)
1ee0     1ee0:	9c                   	pushf
1ee1     1ee1:	58                   	pop    %rax
1ee2     1ee2:	fa                   	cli
1ee3     1ee3:	fb                   	sti
1ee4     1ee4:	c6 07 00             	movb   $0x0,(%rdi)
1ee7     1ee7:	9c                   	pushf
1ee8     1ee8:	58                   	pop    %rax
1ee9     1ee9:	fa                   	cli
1eea     1eea:	fb                   	sti
1eeb     1eeb:	9c                   	pushf
1eec     1eec:	58                   	pop    %rax
1eed     1eed:	fa                   	cli
1eee     1eee:	fb                   	sti
1eef     1eef:	9c                   	pushf
1ef0     1ef0:	58                   	pop    %rax
1ef1     1ef1:	fa                   	cli
1ef2     1ef2:	fb                   	sti
1ef3     1ef3:	9c                   	pushf
1ef4     1ef4:	58                   	pop    %rax
1ef5     1ef5:	fa                   	cli
1ef6     1ef6:	9c                   	pushf
1ef7     1ef7:	58                   	pop    %rax
1ef8     1ef8:	fb                   	sti
1ef9     1ef9:	9c                   	pushf
1efa     1efa:	58                   	pop    %rax
1efb     1efb:	fa                   	cli
1efc     1efc:	9c                   	pushf
1efd     1efd:	58                   	pop    %rax
1efe     1efe:	fb                   	sti
1eff     1eff:	9c                   	pushf
1f00     1f00:	58                   	pop    %rax
1f01     1f01:	fa                   	cli
1f02     1f02:	9c                   	pushf
1f03     1f03:	58                   	pop    %rax
1f04     1f04:	fb                   	sti
1f05     1f05:	9c                   	pushf
1f06     1f06:	58                   	pop    %rax
1f07     1f07:	9c                   	pushf
1f08     1f08:	58                   	pop    %rax
1f09     1f09:	9c                   	pushf
1f0a     1f0a:	58                   	pop    %rax
1f0b     1f0b:	9c                   	pushf
1f0c     1f0c:	58                   	pop    %rax
1f0d     1f0d:	9c                   	pushf
1f0e     1f0e:	58                   	pop    %rax
1f0f     1f0f:	9c                   	pushf
1f10     1f10:	58                   	pop    %rax
1f11     1f11:	9c                   	pushf
1f12     1f12:	58                   	pop    %rax
1f13     1f13:	9c                   	pushf
1f14     1f14:	58                   	pop    %rax
1f15     1f15:	9c                   	pushf
1f16     1f16:	58                   	pop    %rax
1f17     1f17:	9c                   	pushf
1f18     1f18:	58                   	pop    %rax
1f19     1f19:	9c                   	pushf
1f1a     1f1a:	58                   	pop    %rax
1f1b     1f1b:	9c                   	pushf
1f1c     1f1c:	58                   	pop    %rax
1f1d     1f1d:	9c                   	pushf
1f1e     1f1e:	58                   	pop    %rax
1f1f     1f1f:	9c                   	pushf
1f20     1f20:	58                   	pop    %rax
1f21     1f21:	9c                   	pushf
1f22     1f22:	58                   	pop    %rax
1f23     1f23:	9c                   	pushf
1f24     1f24:	58                   	pop    %rax
1f25     1f25:	9c                   	pushf
1f26     1f26:	58                   	pop    %rax
1f27     1f27:	9c                   	pushf
1f28     1f28:	58                   	pop    %rax
1f29     1f29:	9c                   	pushf
1f2a     1f2a:	58                   	pop    %rax
1f2b     1f2b:	c6 07 00             	movb   $0x0,(%rdi)
1f2e     1f2e:	9c                   	pushf
1f2f     1f2f:	58                   	pop    %rax
1f30     1f30:	9c                   	pushf
1f31     1f31:	58                   	pop    %rax
1f32     1f32:	fa                   	cli
1f33     1f33:	9c                   	pushf
1f34     1f34:	58                   	pop    %rax
1f35     1f35:	fb                   	sti
1f36     1f36:	9c                   	pushf
1f37     1f37:	58                   	pop    %rax
1f38     1f38:	fa                   	cli
1f39     1f39:	c6 07 00             	movb   $0x0,(%rdi)
1f3c     1f3c:	9c                   	pushf
1f3d     1f3d:	58                   	pop    %rax
1f3e     1f3e:	fb                   	sti
1f3f     1f3f:	9c                   	pushf
1f40     1f40:	58                   	pop    %rax
1f41     1f41:	fa                   	cli
1f42     1f42:	c6 07 00             	movb   $0x0,(%rdi)
1f45     1f45:	9c                   	pushf
1f46     1f46:	58                   	pop    %rax
1f47     1f47:	fb                   	sti
1f48     1f48:	9c                   	pushf
1f49     1f49:	58                   	pop    %rax
1f4a     1f4a:	9c                   	pushf
1f4b     1f4b:	58                   	pop    %rax
1f4c     1f4c:	fa                   	cli
1f4d     1f4d:	fb                   	sti
1f4e     1f4e:	9c                   	pushf
1f4f     1f4f:	58                   	pop    %rax
1f50     1f50:	9c                   	pushf
1f51     1f51:	58                   	pop    %rax
1f52     1f52:	9c                   	pushf
1f53     1f53:	58                   	pop    %rax
1f54     1f54:	9c                   	pushf
1f55     1f55:	58                   	pop    %rax
1f56     1f56:	fa                   	cli
1f57     1f57:	fb                   	sti
1f58     1f58:	9c                   	pushf
1f59     1f59:	58                   	pop    %rax
1f5a     1f5a:	fa                   	cli
1f5b     1f5b:	c6 07 00             	movb   $0x0,(%rdi)
1f5e     1f5e:	9c                   	pushf
1f5f     1f5f:	58                   	pop    %rax
1f60     1f60:	fb                   	sti
1f61     1f61:	c6 07 00             	movb   $0x0,(%rdi)
1f64     1f64:	fb                   	sti
1f65     1f65:	9c                   	pushf
1f66     1f66:	58                   	pop    %rax
1f67     1f67:	fa                   	cli
1f68     1f68:	9c                   	pushf
1f69     1f69:	58                   	pop    %rax
1f6a     1f6a:	fa                   	cli
1f6b     1f6b:	c6 07 00             	movb   $0x0,(%rdi)
1f6e     1f6e:	9c                   	pushf
1f6f     1f6f:	58                   	pop    %rax
1f70     1f70:	fb                   	sti
1f71     1f71:	9c                   	pushf
1f72     1f72:	58                   	pop    %rax
1f73     1f73:	9c                   	pushf
1f74     1f74:	58                   	pop    %rax
1f75     1f75:	9c                   	pushf
1f76     1f76:	58                   	pop    %rax
1f77     1f77:	9c                   	pushf
1f78     1f78:	58                   	pop    %rax
1f79     1f79:	fa                   	cli
1f7a     1f7a:	9c                   	pushf
1f7b     1f7b:	58                   	pop    %rax
1f7c     1f7c:	fb                   	sti
1f7d     1f7d:	9c                   	pushf
1f7e     1f7e:	58                   	pop    %rax
1f7f     1f7f:	fa                   	cli
1f80     1f80:	9c                   	pushf
1f81     1f81:	58                   	pop    %rax
1f82     1f82:	fb                   	sti
1f83     1f83:	9c                   	pushf
1f84     1f84:	58                   	pop    %rax
1f85     1f85:	fa                   	cli
1f86     1f86:	9c                   	pushf
1f87     1f87:	58                   	pop    %rax
1f88     1f88:	fb                   	sti
1f89     1f89:	9c                   	pushf
1f8a     1f8a:	58                   	pop    %rax
1f8b     1f8b:	fa                   	cli
1f8c     1f8c:	9c                   	pushf
1f8d     1f8d:	58                   	pop    %rax
1f8e     1f8e:	fb                   	sti
1f8f     1f8f:	9c                   	pushf
1f90     1f90:	58                   	pop    %rax
1f91     1f91:	fa                   	cli
1f92     1f92:	9c                   	pushf
1f93     1f93:	58                   	pop    %rax
1f94     1f94:	fb                   	sti
1f95     1f95:	9c                   	pushf
1f96     1f96:	58                   	pop    %rax
1f97     1f97:	9c                   	pushf
1f98     1f98:	58                   	pop    %rax
1f99     1f99:	9c                   	pushf
1f9a     1f9a:	58                   	pop    %rax
1f9b     1f9b:	9c                   	pushf
1f9c     1f9c:	58                   	pop    %rax
1f9d     1f9d:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
1fa7     1fa7:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
1fb1     1fb1:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
1fbb     1fbb:	48 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbp
1fc5     1fc5:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
1fcf     1fcf:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
1fd9     1fd9:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
1fe3     1fe3:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
1fed     1fed:	9c                   	pushf
1fee     1fee:	58                   	pop    %rax
1fef     1fef:	9c                   	pushf
1ff0     1ff0:	58                   	pop    %rax
1ff1     1ff1:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
1ffb     1ffb:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
2005     2005:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
200f     200f:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
2019     2019:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
2023     2023:	48 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbp
202d     202d:	9c                   	pushf
202e     202e:	58                   	pop    %rax
202f     202f:	fa                   	cli
2030     2030:	fb                   	sti
2031     2031:	9c                   	pushf
2032     2032:	58                   	pop    %rax
2033     2033:	e9 00 00 00 00       	jmp    2038 <.altinstr_replacement+0x2038>	2034: R_X86_64_PC32	.text+0x86e878
2038     2038:	9c                   	pushf
2039     2039:	58                   	pop    %rax
203a     203a:	9c                   	pushf
203b     203b:	58                   	pop    %rax
203c     203c:	fa                   	cli
203d     203d:	c6 07 00             	movb   $0x0,(%rdi)
2040     2040:	9c                   	pushf
2041     2041:	58                   	pop    %rax
2042     2042:	fb                   	sti
2043     2043:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
204d     204d:	9c                   	pushf
204e     204e:	58                   	pop    %rax
204f     204f:	9c                   	pushf
2050     2050:	58                   	pop    %rax
2051     2051:	fa                   	cli
2052     2052:	9c                   	pushf
2053     2053:	58                   	pop    %rax
2054     2054:	fb                   	sti
2055     2055:	9c                   	pushf
2056     2056:	58                   	pop    %rax
2057     2057:	fa                   	cli
2058     2058:	9c                   	pushf
2059     2059:	58                   	pop    %rax
205a     205a:	fb                   	sti
205b     205b:	9c                   	pushf
205c     205c:	58                   	pop    %rax
205d     205d:	fa                   	cli
205e     205e:	9c                   	pushf
205f     205f:	58                   	pop    %rax
2060     2060:	fb                   	sti
2061     2061:	0f 0d 0b             	prefetchw (%rbx)
2064     2064:	9c                   	pushf
2065     2065:	58                   	pop    %rax
2066     2066:	9c                   	pushf
2067     2067:	58                   	pop    %rax
2068     2068:	fa                   	cli
2069     2069:	9c                   	pushf
206a     206a:	58                   	pop    %rax
206b     206b:	fb                   	sti
206c     206c:	e9 00 00 00 00       	jmp    2071 <.altinstr_replacement+0x2071>	206d: R_X86_64_PC32	.text+0x94081e
2071     2071:	48 89 f8             	mov    %rdi,%rax
2074     2074:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
207e     207e:	e9 00 00 00 00       	jmp    2083 <.altinstr_replacement+0x2083>	207f: R_X86_64_PC32	.text+0x946d5e
2083     2083:	e9 00 00 00 00       	jmp    2088 <.altinstr_replacement+0x2088>	2084: R_X86_64_PC32	.text+0x94ddf0
2088     2088:	48 89 f8             	mov    %rdi,%rax
208b     208b:	48 89 f8             	mov    %rdi,%rax
208e     208e:	48 89 f8             	mov    %rdi,%rax
2091     2091:	48 89 f8             	mov    %rdi,%rax
2094     2094:	9c                   	pushf
2095     2095:	58                   	pop    %rax
2096     2096:	fa                   	cli
2097     2097:	9c                   	pushf
2098     2098:	58                   	pop    %rax
2099     2099:	fb                   	sti
209a     209a:	9c                   	pushf
209b     209b:	58                   	pop    %rax
209c     209c:	fa                   	cli
209d     209d:	9c                   	pushf
209e     209e:	58                   	pop    %rax
209f     209f:	fb                   	sti
20a0     20a0:	9c                   	pushf
20a1     20a1:	58                   	pop    %rax
20a2     20a2:	fb                   	sti
20a3     20a3:	9c                   	pushf
20a4     20a4:	58                   	pop    %rax
20a5     20a5:	fa                   	cli
20a6     20a6:	9c                   	pushf
20a7     20a7:	58                   	pop    %rax
20a8     20a8:	fb                   	sti
20a9     20a9:	9c                   	pushf
20aa     20aa:	58                   	pop    %rax
20ab     20ab:	fa                   	cli
20ac     20ac:	9c                   	pushf
20ad     20ad:	58                   	pop    %rax
20ae     20ae:	fb                   	sti
20af     20af:	9c                   	pushf
20b0     20b0:	58                   	pop    %rax
20b1     20b1:	fa                   	cli
20b2     20b2:	9c                   	pushf
20b3     20b3:	58                   	pop    %rax
20b4     20b4:	fb                   	sti
20b5     20b5:	f3 48 0f b8 c7       	popcnt %rdi,%rax
20ba     20ba:	f3 48 0f b8 c7       	popcnt %rdi,%rax
20bf     20bf:	49 be 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r14
20c9     20c9:	49 be 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r14
20d3     20d3:	9c                   	pushf
20d4     20d4:	58                   	pop    %rax
20d5     20d5:	48 89 f8             	mov    %rdi,%rax
20d8     20d8:	48 be 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rsi
20e2     20e2:	48 89 f8             	mov    %rdi,%rax
20e5     20e5:	9c                   	pushf
20e6     20e6:	58                   	pop    %rax
20e7     20e7:	9c                   	pushf
20e8     20e8:	58                   	pop    %rax
20e9     20e9:	fa                   	cli
20ea     20ea:	9c                   	pushf
20eb     20eb:	58                   	pop    %rax
20ec     20ec:	fb                   	sti
20ed     20ed:	9c                   	pushf
20ee     20ee:	58                   	pop    %rax
20ef     20ef:	9c                   	pushf
20f0     20f0:	58                   	pop    %rax
20f1     20f1:	fa                   	cli
20f2     20f2:	9c                   	pushf
20f3     20f3:	58                   	pop    %rax
20f4     20f4:	fb                   	sti
20f5     20f5:	9c                   	pushf
20f6     20f6:	58                   	pop    %rax
20f7     20f7:	fa                   	cli
20f8     20f8:	9c                   	pushf
20f9     20f9:	58                   	pop    %rax
20fa     20fa:	fb                   	sti
20fb     20fb:	e9 00 00 00 00       	jmp    2100 <.altinstr_replacement+0x2100>	20fc: R_X86_64_PC32	.text+0x98d6ed
2100     2100:	e9 00 00 00 00       	jmp    2105 <.altinstr_replacement+0x2105>	2101: R_X86_64_PC32	.text+0x98d70e
2105     2105:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
210f     210f:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
2119     2119:	0f 01 cb             	stac
211c     211c:	0f ae e8             	lfence
211f     211f:	0f 01 ca             	clac
2122     2122:	0f 01 ca             	clac
2125     2125:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
212f     212f:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
2139     2139:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
2143     2143:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
214d     214d:	9c                   	pushf
214e     214e:	58                   	pop    %rax
214f     214f:	fa                   	cli
2150     2150:	9c                   	pushf
2151     2151:	58                   	pop    %rax
2152     2152:	fb                   	sti
2153     2153:	9c                   	pushf
2154     2154:	58                   	pop    %rax
2155     2155:	fa                   	cli
2156     2156:	9c                   	pushf
2157     2157:	58                   	pop    %rax
2158     2158:	fb                   	sti
2159     2159:	e9 00 00 00 00       	jmp    215e <.altinstr_replacement+0x215e>	215a: R_X86_64_PC32	.text+0x9a6c33
215e     215e:	e9 00 00 00 00       	jmp    2163 <.altinstr_replacement+0x2163>	215f: R_X86_64_PC32	.text+0x9a6c8c
2163     2163:	48 89 f8             	mov    %rdi,%rax
2166     2166:	48 89 f8             	mov    %rdi,%rax
2169     2169:	48 89 f8             	mov    %rdi,%rax
216c     216c:	48 89 f8             	mov    %rdi,%rax
216f     216f:	48 89 f8             	mov    %rdi,%rax
2172     2172:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
217c     217c:	e8 00 00 00 00       	call   2181 <.altinstr_replacement+0x2181>	217d: R_X86_64_PLT32	copy_user_generic_string-0x4
2181     2181:	e8 00 00 00 00       	call   2186 <.altinstr_replacement+0x2186>	2182: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
2186     2186:	49 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r13
2190     2190:	e8 00 00 00 00       	call   2195 <.altinstr_replacement+0x2195>	2191: R_X86_64_PLT32	copy_user_generic_string-0x4
2195     2195:	e8 00 00 00 00       	call   219a <.altinstr_replacement+0x219a>	2196: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
219a     219a:	9c                   	pushf
219b     219b:	58                   	pop    %rax
219c     219c:	fa                   	cli
219d     219d:	9c                   	pushf
219e     219e:	58                   	pop    %rax
219f     219f:	fb                   	sti
21a0     21a0:	9c                   	pushf
21a1     21a1:	58                   	pop    %rax
21a2     21a2:	fa                   	cli
21a3     21a3:	9c                   	pushf
21a4     21a4:	58                   	pop    %rax
21a5     21a5:	fb                   	sti
21a6     21a6:	9c                   	pushf
21a7     21a7:	58                   	pop    %rax
21a8     21a8:	fa                   	cli
21a9     21a9:	9c                   	pushf
21aa     21aa:	58                   	pop    %rax
21ab     21ab:	fb                   	sti
21ac     21ac:	9c                   	pushf
21ad     21ad:	58                   	pop    %rax
21ae     21ae:	fa                   	cli
21af     21af:	9c                   	pushf
21b0     21b0:	58                   	pop    %rax
21b1     21b1:	fb                   	sti
21b2     21b2:	9c                   	pushf
21b3     21b3:	58                   	pop    %rax
21b4     21b4:	fa                   	cli
21b5     21b5:	9c                   	pushf
21b6     21b6:	58                   	pop    %rax
21b7     21b7:	fb                   	sti
21b8     21b8:	48 89 f8             	mov    %rdi,%rax
21bb     21bb:	e9 00 00 00 00       	jmp    21c0 <.altinstr_replacement+0x21c0>	21bc: R_X86_64_PC32	.text+0x9e8c14
21c0     21c0:	e9 00 00 00 00       	jmp    21c5 <.altinstr_replacement+0x21c5>	21c1: R_X86_64_PC32	.text+0x9e8d68
21c5     21c5:	0f 0d 4d f8          	prefetchw -0x8(%rbp)
21c9     21c9:	48 89 f8             	mov    %rdi,%rax
21cc     21cc:	48 89 f8             	mov    %rdi,%rax
21cf     21cf:	48 89 f8             	mov    %rdi,%rax
21d2     21d2:	48 89 f8             	mov    %rdi,%rax
21d5     21d5:	48 89 f8             	mov    %rdi,%rax
21d8     21d8:	48 89 f8             	mov    %rdi,%rax
21db     21db:	48 89 f8             	mov    %rdi,%rax
21de     21de:	e9 00 00 00 00       	jmp    21e3 <.altinstr_replacement+0x21e3>	21df: R_X86_64_PC32	.text+0x9f57a9
21e3     21e3:	e9 00 00 00 00       	jmp    21e8 <.altinstr_replacement+0x21e8>	21e4: R_X86_64_PC32	.text+0x9f5464
21e8     21e8:	48 89 f8             	mov    %rdi,%rax
21eb     21eb:	48 89 f8             	mov    %rdi,%rax
21ee     21ee:	48 89 f8             	mov    %rdi,%rax
21f1     21f1:	48 89 f8             	mov    %rdi,%rax
21f4     21f4:	48 89 f8             	mov    %rdi,%rax
21f7     21f7:	48 89 f8             	mov    %rdi,%rax
21fa     21fa:	48 89 f8             	mov    %rdi,%rax
21fd     21fd:	48 89 f8             	mov    %rdi,%rax
2200     2200:	f3 48 0f b8 c7       	popcnt %rdi,%rax
2205     2205:	48 89 f8             	mov    %rdi,%rax
2208     2208:	48 89 f8             	mov    %rdi,%rax
220b     220b:	9c                   	pushf
220c     220c:	58                   	pop    %rax
220d     220d:	fa                   	cli
220e     220e:	9c                   	pushf
220f     220f:	58                   	pop    %rax
2210     2210:	fb                   	sti
2211     2211:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
221b     221b:	49 bf 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r15
2225     2225:	49 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r13
222f     222f:	49 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r13
2239     2239:	e8 00 00 00 00       	call   223e <.altinstr_replacement+0x223e>	223a: R_X86_64_PLT32	clear_page_rep-0x4
223e     223e:	e8 00 00 00 00       	call   2243 <.altinstr_replacement+0x2243>	223f: R_X86_64_PLT32	clear_page_erms-0x4
2243     2243:	e8 00 00 00 00       	call   2248 <.altinstr_replacement+0x2248>	2244: R_X86_64_PLT32	clear_page_rep-0x4
2248     2248:	e8 00 00 00 00       	call   224d <.altinstr_replacement+0x224d>	2249: R_X86_64_PLT32	clear_page_erms-0x4
224d     224d:	e8 00 00 00 00       	call   2252 <.altinstr_replacement+0x2252>	224e: R_X86_64_PLT32	clear_page_rep-0x4
2252     2252:	e8 00 00 00 00       	call   2257 <.altinstr_replacement+0x2257>	2253: R_X86_64_PLT32	clear_page_erms-0x4
2257     2257:	e9 00 00 00 00       	jmp    225c <.altinstr_replacement+0x225c>	2258: R_X86_64_PC32	.text+0xa21b70
225c     225c:	e9 00 00 00 00       	jmp    2261 <.altinstr_replacement+0x2261>	225d: R_X86_64_PC32	.init.text+0xd5a25
2261     2261:	48 89 f8             	mov    %rdi,%rax
2264     2264:	e9 00 00 00 00       	jmp    2269 <.altinstr_replacement+0x2269>	2265: R_X86_64_PC32	.text.unlikely+0x7076c
2269     2269:	48 89 f8             	mov    %rdi,%rax
226c     226c:	9c                   	pushf
226d     226d:	58                   	pop    %rax
226e     226e:	fa                   	cli
226f     226f:	9c                   	pushf
2270     2270:	58                   	pop    %rax
2271     2271:	fb                   	sti
2272     2272:	e9 00 00 00 00       	jmp    2277 <.altinstr_replacement+0x2277>	2273: R_X86_64_PC32	.text.unlikely+0x708e8
2277     2277:	e9 00 00 00 00       	jmp    227c <.altinstr_replacement+0x227c>	2278: R_X86_64_PC32	.text.unlikely+0x7084b
227c     227c:	48 89 f8             	mov    %rdi,%rax
227f     227f:	48 89 f8             	mov    %rdi,%rax
2282     2282:	48 89 f8             	mov    %rdi,%rax
2285     2285:	e9 00 00 00 00       	jmp    228a <.altinstr_replacement+0x228a>	2286: R_X86_64_PC32	.init.text+0xd8f01
228a     228a:	e9 00 00 00 00       	jmp    228f <.altinstr_replacement+0x228f>	228b: R_X86_64_PC32	.init.text+0xd8f7c
228f     228f:	e9 00 00 00 00       	jmp    2294 <.altinstr_replacement+0x2294>	2290: R_X86_64_PC32	.init.text+0xd94e6
2294     2294:	48 89 f8             	mov    %rdi,%rax
2297     2297:	48 89 f8             	mov    %rdi,%rax
229a     229a:	9c                   	pushf
229b     229b:	58                   	pop    %rax
229c     229c:	fa                   	cli
229d     229d:	9c                   	pushf
229e     229e:	58                   	pop    %rax
229f     229f:	fb                   	sti
22a0     22a0:	9c                   	pushf
22a1     22a1:	58                   	pop    %rax
22a2     22a2:	fa                   	cli
22a3     22a3:	9c                   	pushf
22a4     22a4:	58                   	pop    %rax
22a5     22a5:	fb                   	sti
22a6     22a6:	e9 00 00 00 00       	jmp    22ab <.altinstr_replacement+0x22ab>	22a7: R_X86_64_PC32	.text+0xa4793a
22ab     22ab:	e9 00 00 00 00       	jmp    22b0 <.altinstr_replacement+0x22b0>	22ac: R_X86_64_PC32	.text+0xa47985
22b0     22b0:	9c                   	pushf
22b1     22b1:	58                   	pop    %rax
22b2     22b2:	fa                   	cli
22b3     22b3:	9c                   	pushf
22b4     22b4:	58                   	pop    %rax
22b5     22b5:	fb                   	sti
22b6     22b6:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
22c0     22c0:	0f 01 cb             	stac
22c3     22c3:	0f ae e8             	lfence
22c6     22c6:	0f 01 ca             	clac
22c9     22c9:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
22d3     22d3:	0f 01 cb             	stac
22d6     22d6:	0f ae e8             	lfence
22d9     22d9:	0f 01 ca             	clac
22dc     22dc:	e9 00 00 00 00       	jmp    22e1 <.altinstr_replacement+0x22e1>	22dd: R_X86_64_PC32	.text+0xa5b35e
22e1     22e1:	48 89 f8             	mov    %rdi,%rax
22e4     22e4:	48 89 f8             	mov    %rdi,%rax
22e7     22e7:	e9 00 00 00 00       	jmp    22ec <.altinstr_replacement+0x22ec>	22e8: R_X86_64_PC32	.text+0xa5bda6
22ec     22ec:	e9 00 00 00 00       	jmp    22f1 <.altinstr_replacement+0x22f1>	22ed: R_X86_64_PC32	.text+0xa5c28a
22f1     22f1:	48 89 f8             	mov    %rdi,%rax
22f4     22f4:	48 89 f8             	mov    %rdi,%rax
22f7     22f7:	48 89 f8             	mov    %rdi,%rax
22fa     22fa:	e9 00 00 00 00       	jmp    22ff <.altinstr_replacement+0x22ff>	22fb: R_X86_64_PC32	.text+0xa60d43
22ff     22ff:	48 89 f8             	mov    %rdi,%rax
2302     2302:	48 89 f8             	mov    %rdi,%rax
2305     2305:	e9 00 00 00 00       	jmp    230a <.altinstr_replacement+0x230a>	2306: R_X86_64_PC32	.text+0xa60f19
230a     230a:	e9 00 00 00 00       	jmp    230f <.altinstr_replacement+0x230f>	230b: R_X86_64_PC32	.text+0xa6127e
230f     230f:	48 89 f8             	mov    %rdi,%rax
2312     2312:	48 89 f8             	mov    %rdi,%rax
2315     2315:	48 89 f8             	mov    %rdi,%rax
2318     2318:	48 89 f8             	mov    %rdi,%rax
231b     231b:	48 89 f8             	mov    %rdi,%rax
231e     231e:	48 89 f8             	mov    %rdi,%rax
2321     2321:	48 89 f8             	mov    %rdi,%rax
2324     2324:	48 89 f8             	mov    %rdi,%rax
2327     2327:	48 89 f8             	mov    %rdi,%rax
232a     232a:	48 89 f8             	mov    %rdi,%rax
232d     232d:	48 89 f8             	mov    %rdi,%rax
2330     2330:	48 89 f8             	mov    %rdi,%rax
2333     2333:	48 89 f8             	mov    %rdi,%rax
2336     2336:	48 89 f8             	mov    %rdi,%rax
2339     2339:	48 89 f8             	mov    %rdi,%rax
233c     233c:	e9 00 00 00 00       	jmp    2341 <.altinstr_replacement+0x2341>	233d: R_X86_64_PC32	.text+0xa63723
2341     2341:	e9 00 00 00 00       	jmp    2346 <.altinstr_replacement+0x2346>	2342: R_X86_64_PC32	.text+0xa63791
2346     2346:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
2350     2350:	e9 00 00 00 00       	jmp    2355 <.altinstr_replacement+0x2355>	2351: R_X86_64_PC32	.text+0xa6392a
2355     2355:	48 89 f8             	mov    %rdi,%rax
2358     2358:	48 89 f8             	mov    %rdi,%rax
235b     235b:	48 89 f8             	mov    %rdi,%rax
235e     235e:	48 89 f8             	mov    %rdi,%rax
2361     2361:	48 89 f8             	mov    %rdi,%rax
2364     2364:	48 89 f8             	mov    %rdi,%rax
2367     2367:	48 89 f8             	mov    %rdi,%rax
236a     236a:	e9 00 00 00 00       	jmp    236f <.altinstr_replacement+0x236f>	236b: R_X86_64_PC32	.text+0xa66371
236f     236f:	48 89 f8             	mov    %rdi,%rax
2372     2372:	48 89 f8             	mov    %rdi,%rax
2375     2375:	48 89 f8             	mov    %rdi,%rax
2378     2378:	48 89 f8             	mov    %rdi,%rax
237b     237b:	48 89 f8             	mov    %rdi,%rax
237e     237e:	48 89 f8             	mov    %rdi,%rax
2381     2381:	48 89 f8             	mov    %rdi,%rax
2384     2384:	48 89 f8             	mov    %rdi,%rax
2387     2387:	e9 00 00 00 00       	jmp    238c <.altinstr_replacement+0x238c>	2388: R_X86_64_PC32	.text+0xa66bb1
238c     238c:	48 89 f8             	mov    %rdi,%rax
238f     238f:	48 89 f8             	mov    %rdi,%rax
2392     2392:	48 89 f8             	mov    %rdi,%rax
2395     2395:	48 89 f8             	mov    %rdi,%rax
2398     2398:	48 89 f8             	mov    %rdi,%rax
239b     239b:	48 89 f8             	mov    %rdi,%rax
239e     239e:	48 89 f8             	mov    %rdi,%rax
23a1     23a1:	48 89 f8             	mov    %rdi,%rax
23a4     23a4:	48 89 f8             	mov    %rdi,%rax
23a7     23a7:	48 89 f8             	mov    %rdi,%rax
23aa     23aa:	e9 00 00 00 00       	jmp    23af <.altinstr_replacement+0x23af>	23ab: R_X86_64_PC32	.text+0xa67b41
23af     23af:	48 89 f8             	mov    %rdi,%rax
23b2     23b2:	e9 00 00 00 00       	jmp    23b7 <.altinstr_replacement+0x23b7>	23b3: R_X86_64_PC32	.text+0xa67e4c
23b7     23b7:	9c                   	pushf
23b8     23b8:	58                   	pop    %rax
23b9     23b9:	fa                   	cli
23ba     23ba:	9c                   	pushf
23bb     23bb:	58                   	pop    %rax
23bc     23bc:	fb                   	sti
23bd     23bd:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
23c7     23c7:	e9 00 00 00 00       	jmp    23cc <.altinstr_replacement+0x23cc>	23c8: R_X86_64_PC32	.text+0xa6cbc0
23cc     23cc:	48 89 f8             	mov    %rdi,%rax
23cf     23cf:	48 89 f8             	mov    %rdi,%rax
23d2     23d2:	e9 00 00 00 00       	jmp    23d7 <.altinstr_replacement+0x23d7>	23d3: R_X86_64_PC32	.text+0xa6d0de
23d7     23d7:	48 89 f8             	mov    %rdi,%rax
23da     23da:	48 89 f8             	mov    %rdi,%rax
23dd     23dd:	48 89 f8             	mov    %rdi,%rax
23e0     23e0:	e9 00 00 00 00       	jmp    23e5 <.altinstr_replacement+0x23e5>	23e1: R_X86_64_PC32	.text+0xa6d46f
23e5     23e5:	e9 00 00 00 00       	jmp    23ea <.altinstr_replacement+0x23ea>	23e6: R_X86_64_PC32	.text+0xa6d4c8
23ea     23ea:	9c                   	pushf
23eb     23eb:	58                   	pop    %rax
23ec     23ec:	fa                   	cli
23ed     23ed:	9c                   	pushf
23ee     23ee:	58                   	pop    %rax
23ef     23ef:	fb                   	sti
23f0     23f0:	9c                   	pushf
23f1     23f1:	58                   	pop    %rax
23f2     23f2:	fa                   	cli
23f3     23f3:	9c                   	pushf
23f4     23f4:	58                   	pop    %rax
23f5     23f5:	fb                   	sti
23f6     23f6:	48 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbp
2400     2400:	48 89 f8             	mov    %rdi,%rax
2403     2403:	48 89 f8             	mov    %rdi,%rax
2406     2406:	48 89 f8             	mov    %rdi,%rax
2409     2409:	48 89 f8             	mov    %rdi,%rax
240c     240c:	48 89 f8             	mov    %rdi,%rax
240f     240f:	48 89 f8             	mov    %rdi,%rax
2412     2412:	e9 00 00 00 00       	jmp    2417 <.altinstr_replacement+0x2417>	2413: R_X86_64_PC32	.text+0xa70f56
2417     2417:	e9 00 00 00 00       	jmp    241c <.altinstr_replacement+0x241c>	2418: R_X86_64_PC32	.text+0xa70f61
241c     241c:	48 89 f8             	mov    %rdi,%rax
241f     241f:	48 89 f8             	mov    %rdi,%rax
2422     2422:	48 89 f8             	mov    %rdi,%rax
2425     2425:	48 89 f8             	mov    %rdi,%rax
2428     2428:	48 89 f8             	mov    %rdi,%rax
242b     242b:	e9 00 00 00 00       	jmp    2430 <.altinstr_replacement+0x2430>	242c: R_X86_64_PC32	.text+0xa71cdf
2430     2430:	e9 00 00 00 00       	jmp    2435 <.altinstr_replacement+0x2435>	2431: R_X86_64_PC32	.text+0xa71d4a
2435     2435:	e9 00 00 00 00       	jmp    243a <.altinstr_replacement+0x243a>	2436: R_X86_64_PC32	.text+0xa71c62
243a     243a:	48 89 f8             	mov    %rdi,%rax
243d     243d:	48 89 f8             	mov    %rdi,%rax
2440     2440:	e9 00 00 00 00       	jmp    2445 <.altinstr_replacement+0x2445>	2441: R_X86_64_PC32	.text+0xa72553
2445     2445:	48 89 f8             	mov    %rdi,%rax
2448     2448:	48 89 f8             	mov    %rdi,%rax
244b     244b:	48 89 f8             	mov    %rdi,%rax
244e     244e:	e8 00 00 00 00       	call   2453 <.altinstr_replacement+0x2453>	244f: R_X86_64_PLT32	copy_user_generic_string-0x4
2453     2453:	e8 00 00 00 00       	call   2458 <.altinstr_replacement+0x2458>	2454: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
2458     2458:	e8 00 00 00 00       	call   245d <.altinstr_replacement+0x245d>	2459: R_X86_64_PLT32	copy_user_generic_string-0x4
245d     245d:	e8 00 00 00 00       	call   2462 <.altinstr_replacement+0x2462>	245e: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
2462     2462:	e8 00 00 00 00       	call   2467 <.altinstr_replacement+0x2467>	2463: R_X86_64_PLT32	clear_page_rep-0x4
2467     2467:	e8 00 00 00 00       	call   246c <.altinstr_replacement+0x246c>	2468: R_X86_64_PLT32	clear_page_erms-0x4
246c     246c:	e9 00 00 00 00       	jmp    2471 <.altinstr_replacement+0x2471>	246d: R_X86_64_PC32	.text+0xa753d8
2471     2471:	e9 00 00 00 00       	jmp    2476 <.altinstr_replacement+0x2476>	2472: R_X86_64_PC32	.text+0xa75444
2476     2476:	48 89 f8             	mov    %rdi,%rax
2479     2479:	48 89 f8             	mov    %rdi,%rax
247c     247c:	48 89 f8             	mov    %rdi,%rax
247f     247f:	48 89 f8             	mov    %rdi,%rax
2482     2482:	48 89 f8             	mov    %rdi,%rax
2485     2485:	48 89 f8             	mov    %rdi,%rax
2488     2488:	48 89 f8             	mov    %rdi,%rax
248b     248b:	48 89 f8             	mov    %rdi,%rax
248e     248e:	48 89 f8             	mov    %rdi,%rax
2491     2491:	48 89 f8             	mov    %rdi,%rax
2494     2494:	48 89 f8             	mov    %rdi,%rax
2497     2497:	48 89 f8             	mov    %rdi,%rax
249a     249a:	e9 00 00 00 00       	jmp    249f <.altinstr_replacement+0x249f>	249b: R_X86_64_PC32	.text+0xa7a91e
249f     249f:	e9 00 00 00 00       	jmp    24a4 <.altinstr_replacement+0x24a4>	24a0: R_X86_64_PC32	.text+0xa7a929
24a4     24a4:	e9 00 00 00 00       	jmp    24a9 <.altinstr_replacement+0x24a9>	24a5: R_X86_64_PC32	.text+0xa7ac3a
24a9     24a9:	e9 00 00 00 00       	jmp    24ae <.altinstr_replacement+0x24ae>	24aa: R_X86_64_PC32	.text+0xa7aca1
24ae     24ae:	48 89 f8             	mov    %rdi,%rax
24b1     24b1:	48 89 f8             	mov    %rdi,%rax
24b4     24b4:	48 89 f8             	mov    %rdi,%rax
24b7     24b7:	e9 00 00 00 00       	jmp    24bc <.altinstr_replacement+0x24bc>	24b8: R_X86_64_PC32	.text+0xa8222c
24bc     24bc:	e9 00 00 00 00       	jmp    24c1 <.altinstr_replacement+0x24c1>	24bd: R_X86_64_PC32	.text+0xa82262
24c1     24c1:	48 89 f8             	mov    %rdi,%rax
24c4     24c4:	48 89 f8             	mov    %rdi,%rax
24c7     24c7:	48 89 f8             	mov    %rdi,%rax
24ca     24ca:	e9 00 00 00 00       	jmp    24cf <.altinstr_replacement+0x24cf>	24cb: R_X86_64_PC32	.text+0xa834ad
24cf     24cf:	e9 00 00 00 00       	jmp    24d4 <.altinstr_replacement+0x24d4>	24d0: R_X86_64_PC32	.text+0xa83514
24d4     24d4:	e9 00 00 00 00       	jmp    24d9 <.altinstr_replacement+0x24d9>	24d5: R_X86_64_PC32	.text+0xa83559
24d9     24d9:	48 89 f8             	mov    %rdi,%rax
24dc     24dc:	48 89 f8             	mov    %rdi,%rax
24df     24df:	48 89 f8             	mov    %rdi,%rax
24e2     24e2:	e9 00 00 00 00       	jmp    24e7 <.altinstr_replacement+0x24e7>	24e3: R_X86_64_PC32	.text+0xa8486c
24e7     24e7:	e9 00 00 00 00       	jmp    24ec <.altinstr_replacement+0x24ec>	24e8: R_X86_64_PC32	.text+0xa8488e
24ec     24ec:	e9 00 00 00 00       	jmp    24f1 <.altinstr_replacement+0x24f1>	24ed: R_X86_64_PC32	.text+0xa84753
24f1     24f1:	48 89 f8             	mov    %rdi,%rax
24f4     24f4:	48 89 f8             	mov    %rdi,%rax
24f7     24f7:	48 89 f8             	mov    %rdi,%rax
24fa     24fa:	48 89 f8             	mov    %rdi,%rax
24fd     24fd:	48 89 f8             	mov    %rdi,%rax
2500     2500:	48 89 f8             	mov    %rdi,%rax
2503     2503:	48 89 f8             	mov    %rdi,%rax
2506     2506:	e9 00 00 00 00       	jmp    250b <.altinstr_replacement+0x250b>	2507: R_X86_64_PC32	.text+0xa86fa6
250b     250b:	e9 00 00 00 00       	jmp    2510 <.altinstr_replacement+0x2510>	250c: R_X86_64_PC32	.text+0xa87112
2510     2510:	48 89 f8             	mov    %rdi,%rax
2513     2513:	e9 00 00 00 00       	jmp    2518 <.altinstr_replacement+0x2518>	2514: R_X86_64_PC32	.text+0xa882ca
2518     2518:	e9 00 00 00 00       	jmp    251d <.altinstr_replacement+0x251d>	2519: R_X86_64_PC32	.text+0xa882d5
251d     251d:	48 89 f8             	mov    %rdi,%rax
2520     2520:	e8 00 00 00 00       	call   2525 <.altinstr_replacement+0x2525>	2521: R_X86_64_PLT32	clear_page_rep-0x4
2525     2525:	e8 00 00 00 00       	call   252a <.altinstr_replacement+0x252a>	2526: R_X86_64_PLT32	clear_page_erms-0x4
252a     252a:	e8 00 00 00 00       	call   252f <.altinstr_replacement+0x252f>	252b: R_X86_64_PLT32	clear_page_rep-0x4
252f     252f:	e8 00 00 00 00       	call   2534 <.altinstr_replacement+0x2534>	2530: R_X86_64_PLT32	clear_page_erms-0x4
2534     2534:	e8 00 00 00 00       	call   2539 <.altinstr_replacement+0x2539>	2535: R_X86_64_PLT32	clear_page_rep-0x4
2539     2539:	e8 00 00 00 00       	call   253e <.altinstr_replacement+0x253e>	253a: R_X86_64_PLT32	clear_page_erms-0x4
253e     253e:	e8 00 00 00 00       	call   2543 <.altinstr_replacement+0x2543>	253f: R_X86_64_PLT32	clear_page_rep-0x4
2543     2543:	e8 00 00 00 00       	call   2548 <.altinstr_replacement+0x2548>	2544: R_X86_64_PLT32	clear_page_erms-0x4
2548     2548:	e8 00 00 00 00       	call   254d <.altinstr_replacement+0x254d>	2549: R_X86_64_PLT32	clear_page_rep-0x4
254d     254d:	e8 00 00 00 00       	call   2552 <.altinstr_replacement+0x2552>	254e: R_X86_64_PLT32	clear_page_erms-0x4
2552     2552:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
255c     255c:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
2566     2566:	48 89 f8             	mov    %rdi,%rax
2569     2569:	48 89 f8             	mov    %rdi,%rax
256c     256c:	48 89 f8             	mov    %rdi,%rax
256f     256f:	48 89 f8             	mov    %rdi,%rax
2572     2572:	48 89 f8             	mov    %rdi,%rax
2575     2575:	48 89 f8             	mov    %rdi,%rax
2578     2578:	48 89 f8             	mov    %rdi,%rax
257b     257b:	48 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbp
2585     2585:	48 89 f8             	mov    %rdi,%rax
2588     2588:	48 89 f8             	mov    %rdi,%rax
258b     258b:	48 89 f8             	mov    %rdi,%rax
258e     258e:	48 89 f8             	mov    %rdi,%rax
2591     2591:	48 89 f8             	mov    %rdi,%rax
2594     2594:	48 89 f8             	mov    %rdi,%rax
2597     2597:	48 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbp
25a1     25a1:	48 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbp
25ab     25ab:	49 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r13
25b5     25b5:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
25bf     25bf:	48 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbp
25c9     25c9:	48 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbp
25d3     25d3:	e9 00 00 00 00       	jmp    25d8 <.altinstr_replacement+0x25d8>	25d4: R_X86_64_PC32	.text+0xaa67e0
25d8     25d8:	48 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbp
25e2     25e2:	48 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbp
25ec     25ec:	48 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbp
25f6     25f6:	e9 00 00 00 00       	jmp    25fb <.altinstr_replacement+0x25fb>	25f7: R_X86_64_PC32	.text+0xaa951e
25fb     25fb:	48 89 f8             	mov    %rdi,%rax
25fe     25fe:	48 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbp
2608     2608:	e9 00 00 00 00       	jmp    260d <.altinstr_replacement+0x260d>	2609: R_X86_64_PC32	.text+0xaa99dd
260d     260d:	e9 00 00 00 00       	jmp    2612 <.altinstr_replacement+0x2612>	260e: R_X86_64_PC32	.text+0xaa9b8a
2612     2612:	e9 00 00 00 00       	jmp    2617 <.altinstr_replacement+0x2617>	2613: R_X86_64_PC32	.text+0xaa9d99
2617     2617:	e9 00 00 00 00       	jmp    261c <.altinstr_replacement+0x261c>	2618: R_X86_64_PC32	.text+0xaa9fd9
261c     261c:	48 89 f8             	mov    %rdi,%rax
261f     261f:	48 89 f8             	mov    %rdi,%rax
2622     2622:	48 89 f8             	mov    %rdi,%rax
2625     2625:	48 89 f8             	mov    %rdi,%rax
2628     2628:	e9 00 00 00 00       	jmp    262d <.altinstr_replacement+0x262d>	2629: R_X86_64_PC32	.text+0xaaadb3
262d     262d:	e9 00 00 00 00       	jmp    2632 <.altinstr_replacement+0x2632>	262e: R_X86_64_PC32	.text+0xaaae0c
2632     2632:	48 89 f8             	mov    %rdi,%rax
2635     2635:	48 89 f8             	mov    %rdi,%rax
2638     2638:	48 89 f8             	mov    %rdi,%rax
263b     263b:	48 89 f8             	mov    %rdi,%rax
263e     263e:	48 89 f8             	mov    %rdi,%rax
2641     2641:	48 89 f8             	mov    %rdi,%rax
2644     2644:	48 89 f8             	mov    %rdi,%rax
2647     2647:	48 89 f8             	mov    %rdi,%rax
264a     264a:	48 89 f8             	mov    %rdi,%rax
264d     264d:	48 89 f8             	mov    %rdi,%rax
2650     2650:	48 89 f8             	mov    %rdi,%rax
2653     2653:	48 89 f8             	mov    %rdi,%rax
2656     2656:	48 89 f8             	mov    %rdi,%rax
2659     2659:	e9 00 00 00 00       	jmp    265e <.altinstr_replacement+0x265e>	265a: R_X86_64_PC32	.text+0xaadc3d
265e     265e:	e9 00 00 00 00       	jmp    2663 <.altinstr_replacement+0x2663>	265f: R_X86_64_PC32	.text+0xaadcca
2663     2663:	e9 00 00 00 00       	jmp    2668 <.altinstr_replacement+0x2668>	2664: R_X86_64_PC32	.text+0xaadd31
2668     2668:	48 89 f8             	mov    %rdi,%rax
266b     266b:	e9 00 00 00 00       	jmp    2670 <.altinstr_replacement+0x2670>	266c: R_X86_64_PC32	.text+0xaaeb11
2670     2670:	e9 00 00 00 00       	jmp    2675 <.altinstr_replacement+0x2675>	2671: R_X86_64_PC32	.text+0xaaefee
2675     2675:	e9 00 00 00 00       	jmp    267a <.altinstr_replacement+0x267a>	2676: R_X86_64_PC32	.text+0xaaf39e
267a     267a:	48 89 f8             	mov    %rdi,%rax
267d     267d:	e9 00 00 00 00       	jmp    2682 <.altinstr_replacement+0x2682>	267e: R_X86_64_PC32	.text+0xaaf46e
2682     2682:	e9 00 00 00 00       	jmp    2687 <.altinstr_replacement+0x2687>	2683: R_X86_64_PC32	.text+0xaaf4d5
2687     2687:	48 89 f8             	mov    %rdi,%rax
268a     268a:	48 89 f8             	mov    %rdi,%rax
268d     268d:	48 89 f8             	mov    %rdi,%rax
2690     2690:	e9 00 00 00 00       	jmp    2695 <.altinstr_replacement+0x2695>	2691: R_X86_64_PC32	.text+0xaafc92
2695     2695:	48 89 f8             	mov    %rdi,%rax
2698     2698:	48 89 f8             	mov    %rdi,%rax
269b     269b:	48 89 f8             	mov    %rdi,%rax
269e     269e:	48 89 f8             	mov    %rdi,%rax
26a1     26a1:	48 89 f8             	mov    %rdi,%rax
26a4     26a4:	48 89 f8             	mov    %rdi,%rax
26a7     26a7:	48 89 f8             	mov    %rdi,%rax
26aa     26aa:	48 89 f8             	mov    %rdi,%rax
26ad     26ad:	48 89 f8             	mov    %rdi,%rax
26b0     26b0:	48 89 f8             	mov    %rdi,%rax
26b3     26b3:	48 89 f8             	mov    %rdi,%rax
26b6     26b6:	48 89 f8             	mov    %rdi,%rax
26b9     26b9:	48 89 f8             	mov    %rdi,%rax
26bc     26bc:	48 89 f8             	mov    %rdi,%rax
26bf     26bf:	48 89 f8             	mov    %rdi,%rax
26c2     26c2:	48 89 f8             	mov    %rdi,%rax
26c5     26c5:	48 89 f8             	mov    %rdi,%rax
26c8     26c8:	48 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbp
26d2     26d2:	48 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbp
26dc     26dc:	e9 00 00 00 00       	jmp    26e1 <.altinstr_replacement+0x26e1>	26dd: R_X86_64_PC32	.text+0xab45de
26e1     26e1:	48 89 f8             	mov    %rdi,%rax
26e4     26e4:	48 89 f8             	mov    %rdi,%rax
26e7     26e7:	e9 00 00 00 00       	jmp    26ec <.altinstr_replacement+0x26ec>	26e8: R_X86_64_PC32	.text+0xab472d
26ec     26ec:	e9 00 00 00 00       	jmp    26f1 <.altinstr_replacement+0x26f1>	26ed: R_X86_64_PC32	.text+0xab4783
26f1     26f1:	48 89 f8             	mov    %rdi,%rax
26f4     26f4:	48 89 f8             	mov    %rdi,%rax
26f7     26f7:	48 89 f8             	mov    %rdi,%rax
26fa     26fa:	48 89 f8             	mov    %rdi,%rax
26fd     26fd:	48 89 f8             	mov    %rdi,%rax
2700     2700:	e9 00 00 00 00       	jmp    2705 <.altinstr_replacement+0x2705>	2701: R_X86_64_PC32	.text+0xab5905
2705     2705:	48 89 f8             	mov    %rdi,%rax
2708     2708:	48 89 f8             	mov    %rdi,%rax
270b     270b:	48 89 f8             	mov    %rdi,%rax
270e     270e:	48 89 f8             	mov    %rdi,%rax
2711     2711:	48 89 f8             	mov    %rdi,%rax
2714     2714:	48 89 f8             	mov    %rdi,%rax
2717     2717:	48 89 f8             	mov    %rdi,%rax
271a     271a:	48 89 f8             	mov    %rdi,%rax
271d     271d:	48 89 f8             	mov    %rdi,%rax
2720     2720:	48 89 f8             	mov    %rdi,%rax
2723     2723:	48 89 f8             	mov    %rdi,%rax
2726     2726:	48 89 f8             	mov    %rdi,%rax
2729     2729:	48 89 f8             	mov    %rdi,%rax
272c     272c:	48 89 f8             	mov    %rdi,%rax
272f     272f:	48 89 f8             	mov    %rdi,%rax
2732     2732:	48 89 f8             	mov    %rdi,%rax
2735     2735:	48 89 f8             	mov    %rdi,%rax
2738     2738:	48 89 f8             	mov    %rdi,%rax
273b     273b:	48 89 f8             	mov    %rdi,%rax
273e     273e:	48 89 f8             	mov    %rdi,%rax
2741     2741:	48 89 f8             	mov    %rdi,%rax
2744     2744:	48 89 f8             	mov    %rdi,%rax
2747     2747:	e9 00 00 00 00       	jmp    274c <.altinstr_replacement+0x274c>	2748: R_X86_64_PC32	.text+0xab8361
274c     274c:	48 89 f8             	mov    %rdi,%rax
274f     274f:	e9 00 00 00 00       	jmp    2754 <.altinstr_replacement+0x2754>	2750: R_X86_64_PC32	.text+0xab8749
2754     2754:	e9 00 00 00 00       	jmp    2759 <.altinstr_replacement+0x2759>	2755: R_X86_64_PC32	.text+0xab87b9
2759     2759:	48 89 f8             	mov    %rdi,%rax
275c     275c:	48 89 f8             	mov    %rdi,%rax
275f     275f:	48 89 f8             	mov    %rdi,%rax
2762     2762:	e9 00 00 00 00       	jmp    2767 <.altinstr_replacement+0x2767>	2763: R_X86_64_PC32	.text+0xab9b1b
2767     2767:	e9 00 00 00 00       	jmp    276c <.altinstr_replacement+0x276c>	2768: R_X86_64_PC32	.text+0xab9b22
276c     276c:	48 89 f8             	mov    %rdi,%rax
276f     276f:	48 89 f8             	mov    %rdi,%rax
2772     2772:	48 89 f8             	mov    %rdi,%rax
2775     2775:	48 89 f8             	mov    %rdi,%rax
2778     2778:	48 89 f8             	mov    %rdi,%rax
277b     277b:	48 89 f8             	mov    %rdi,%rax
277e     277e:	48 89 f8             	mov    %rdi,%rax
2781     2781:	48 89 f8             	mov    %rdi,%rax
2784     2784:	e9 00 00 00 00       	jmp    2789 <.altinstr_replacement+0x2789>	2785: R_X86_64_PC32	.text+0xabcdde
2789     2789:	48 89 f8             	mov    %rdi,%rax
278c     278c:	48 89 f8             	mov    %rdi,%rax
278f     278f:	48 89 f8             	mov    %rdi,%rax
2792     2792:	e9 00 00 00 00       	jmp    2797 <.altinstr_replacement+0x2797>	2793: R_X86_64_PC32	.text+0xac2fc2
2797     2797:	48 89 f8             	mov    %rdi,%rax
279a     279a:	48 89 f8             	mov    %rdi,%rax
279d     279d:	48 89 f8             	mov    %rdi,%rax
27a0     27a0:	48 89 f8             	mov    %rdi,%rax
27a3     27a3:	48 89 f8             	mov    %rdi,%rax
27a6     27a6:	48 89 f8             	mov    %rdi,%rax
27a9     27a9:	48 89 f8             	mov    %rdi,%rax
27ac     27ac:	48 89 f8             	mov    %rdi,%rax
27af     27af:	48 89 f8             	mov    %rdi,%rax
27b2     27b2:	48 89 f8             	mov    %rdi,%rax
27b5     27b5:	e9 00 00 00 00       	jmp    27ba <.altinstr_replacement+0x27ba>	27b6: R_X86_64_PC32	.text+0xaca910
27ba     27ba:	e9 00 00 00 00       	jmp    27bf <.altinstr_replacement+0x27bf>	27bb: R_X86_64_PC32	.text+0xaca901
27bf     27bf:	48 89 f8             	mov    %rdi,%rax
27c2     27c2:	48 89 f8             	mov    %rdi,%rax
27c5     27c5:	e9 00 00 00 00       	jmp    27ca <.altinstr_replacement+0x27ca>	27c6: R_X86_64_PC32	.text+0xacde0d
27ca     27ca:	e9 00 00 00 00       	jmp    27cf <.altinstr_replacement+0x27cf>	27cb: R_X86_64_PC32	.text+0xace0a7
27cf     27cf:	e9 00 00 00 00       	jmp    27d4 <.altinstr_replacement+0x27d4>	27d0: R_X86_64_PC32	.text+0xace15e
27d4     27d4:	48 89 f8             	mov    %rdi,%rax
27d7     27d7:	48 89 f8             	mov    %rdi,%rax
27da     27da:	9c                   	pushf
27db     27db:	58                   	pop    %rax
27dc     27dc:	fa                   	cli
27dd     27dd:	9c                   	pushf
27de     27de:	58                   	pop    %rax
27df     27df:	fb                   	sti
27e0     27e0:	e9 00 00 00 00       	jmp    27e5 <.altinstr_replacement+0x27e5>	27e1: R_X86_64_PC32	.text+0xacf3da
27e5     27e5:	e9 00 00 00 00       	jmp    27ea <.altinstr_replacement+0x27ea>	27e6: R_X86_64_PC32	.text+0xacf209
27ea     27ea:	48 89 f8             	mov    %rdi,%rax
27ed     27ed:	e9 00 00 00 00       	jmp    27f2 <.altinstr_replacement+0x27f2>	27ee: R_X86_64_PC32	.text+0xad037a
27f2     27f2:	48 89 f8             	mov    %rdi,%rax
27f5     27f5:	48 89 f8             	mov    %rdi,%rax
27f8     27f8:	48 89 f8             	mov    %rdi,%rax
27fb     27fb:	48 89 f8             	mov    %rdi,%rax
27fe     27fe:	48 89 f8             	mov    %rdi,%rax
2801     2801:	48 89 f8             	mov    %rdi,%rax
2804     2804:	e9 00 00 00 00       	jmp    2809 <.altinstr_replacement+0x2809>	2805: R_X86_64_PC32	.text+0xad18f7
2809     2809:	e9 00 00 00 00       	jmp    280e <.altinstr_replacement+0x280e>	280a: R_X86_64_PC32	.text+0xad1914
280e     280e:	e9 00 00 00 00       	jmp    2813 <.altinstr_replacement+0x2813>	280f: R_X86_64_PC32	.text+0xad1cb6
2813     2813:	e9 00 00 00 00       	jmp    2818 <.altinstr_replacement+0x2818>	2814: R_X86_64_PC32	.text+0xad1cef
2818     2818:	48 89 f8             	mov    %rdi,%rax
281b     281b:	48 89 f8             	mov    %rdi,%rax
281e     281e:	e9 00 00 00 00       	jmp    2823 <.altinstr_replacement+0x2823>	281f: R_X86_64_PC32	.text+0xad3595
2823     2823:	e9 00 00 00 00       	jmp    2828 <.altinstr_replacement+0x2828>	2824: R_X86_64_PC32	.text+0xad35fc
2828     2828:	48 89 f8             	mov    %rdi,%rax
282b     282b:	48 89 f8             	mov    %rdi,%rax
282e     282e:	48 89 f8             	mov    %rdi,%rax
2831     2831:	48 89 f8             	mov    %rdi,%rax
2834     2834:	48 89 f8             	mov    %rdi,%rax
2837     2837:	48 89 f8             	mov    %rdi,%rax
283a     283a:	48 89 f8             	mov    %rdi,%rax
283d     283d:	e9 00 00 00 00       	jmp    2842 <.altinstr_replacement+0x2842>	283e: R_X86_64_PC32	.text+0xad7de4
2842     2842:	e9 00 00 00 00       	jmp    2847 <.altinstr_replacement+0x2847>	2843: R_X86_64_PC32	.text+0xad8747
2847     2847:	e9 00 00 00 00       	jmp    284c <.altinstr_replacement+0x284c>	2848: R_X86_64_PC32	.init.text+0xdbe90
284c     284c:	e9 00 00 00 00       	jmp    2851 <.altinstr_replacement+0x2851>	284d: R_X86_64_PC32	.text+0xadbabe
2851     2851:	e9 00 00 00 00       	jmp    2856 <.altinstr_replacement+0x2856>	2852: R_X86_64_PC32	.text+0xadbb46
2856     2856:	e9 00 00 00 00       	jmp    285b <.altinstr_replacement+0x285b>	2857: R_X86_64_PC32	.text+0xadbbb0
285b     285b:	e9 00 00 00 00       	jmp    2860 <.altinstr_replacement+0x2860>	285c: R_X86_64_PC32	.text+0xadbeb8
2860     2860:	e9 00 00 00 00       	jmp    2865 <.altinstr_replacement+0x2865>	2861: R_X86_64_PC32	.text+0xadc20e
2865     2865:	e9 00 00 00 00       	jmp    286a <.altinstr_replacement+0x286a>	2866: R_X86_64_PC32	.text+0xadc802
286a     286a:	e9 00 00 00 00       	jmp    286f <.altinstr_replacement+0x286f>	286b: R_X86_64_PC32	.text+0xadc8bf
286f     286f:	e9 00 00 00 00       	jmp    2874 <.altinstr_replacement+0x2874>	2870: R_X86_64_PC32	.text+0xade103
2874     2874:	e9 00 00 00 00       	jmp    2879 <.altinstr_replacement+0x2879>	2875: R_X86_64_PC32	.text+0xadea34
2879     2879:	e9 00 00 00 00       	jmp    287e <.altinstr_replacement+0x287e>	287a: R_X86_64_PC32	.text+0xadeb2d
287e     287e:	e9 00 00 00 00       	jmp    2883 <.altinstr_replacement+0x2883>	287f: R_X86_64_PC32	.text+0xadebed
2883     2883:	e9 00 00 00 00       	jmp    2888 <.altinstr_replacement+0x2888>	2884: R_X86_64_PC32	.text+0xae06d7
2888     2888:	9c                   	pushf
2889     2889:	58                   	pop    %rax
288a     288a:	fa                   	cli
288b     288b:	9c                   	pushf
288c     288c:	58                   	pop    %rax
288d     288d:	fb                   	sti
288e     288e:	e9 00 00 00 00       	jmp    2893 <.altinstr_replacement+0x2893>	288f: R_X86_64_PC32	.text+0xae41bc
2893     2893:	e9 00 00 00 00       	jmp    2898 <.altinstr_replacement+0x2898>	2894: R_X86_64_PC32	.text+0xae41e9
2898     2898:	e8 00 00 00 00       	call   289d <.altinstr_replacement+0x289d>	2899: R_X86_64_PLT32	clear_page_rep-0x4
289d     289d:	e8 00 00 00 00       	call   28a2 <.altinstr_replacement+0x28a2>	289e: R_X86_64_PLT32	clear_page_erms-0x4
28a2     28a2:	e9 00 00 00 00       	jmp    28a7 <.altinstr_replacement+0x28a7>	28a3: R_X86_64_PC32	.text+0xae4d36
28a7     28a7:	e9 00 00 00 00       	jmp    28ac <.altinstr_replacement+0x28ac>	28a8: R_X86_64_PC32	.text+0xae4f7e
28ac     28ac:	e8 00 00 00 00       	call   28b1 <.altinstr_replacement+0x28b1>	28ad: R_X86_64_PLT32	clear_page_rep-0x4
28b1     28b1:	e8 00 00 00 00       	call   28b6 <.altinstr_replacement+0x28b6>	28b2: R_X86_64_PLT32	clear_page_erms-0x4
28b6     28b6:	e9 00 00 00 00       	jmp    28bb <.altinstr_replacement+0x28bb>	28b7: R_X86_64_PC32	.text+0xae6853
28bb     28bb:	e9 00 00 00 00       	jmp    28c0 <.altinstr_replacement+0x28c0>	28bc: R_X86_64_PC32	.text+0xae727f
28c0     28c0:	e9 00 00 00 00       	jmp    28c5 <.altinstr_replacement+0x28c5>	28c1: R_X86_64_PC32	.text+0xae7476
28c5     28c5:	e9 00 00 00 00       	jmp    28ca <.altinstr_replacement+0x28ca>	28c6: R_X86_64_PC32	.text+0xae7a6d
28ca     28ca:	41 0f 0d 4d 00       	prefetchw 0x0(%r13)
28cf     28cf:	0f 0d 0b             	prefetchw (%rbx)
28d2     28d2:	e9 00 00 00 00       	jmp    28d7 <.altinstr_replacement+0x28d7>	28d3: R_X86_64_PC32	.text+0xae7f8d
28d7     28d7:	e9 00 00 00 00       	jmp    28dc <.altinstr_replacement+0x28dc>	28d8: R_X86_64_PC32	.text+0xae7fba
28dc     28dc:	e9 00 00 00 00       	jmp    28e1 <.altinstr_replacement+0x28e1>	28dd: R_X86_64_PC32	.text+0xae7dfd
28e1     28e1:	e8 00 00 00 00       	call   28e6 <.altinstr_replacement+0x28e6>	28e2: R_X86_64_PLT32	clear_page_rep-0x4
28e6     28e6:	e8 00 00 00 00       	call   28eb <.altinstr_replacement+0x28eb>	28e7: R_X86_64_PLT32	clear_page_erms-0x4
28eb     28eb:	e9 00 00 00 00       	jmp    28f0 <.altinstr_replacement+0x28f0>	28ec: R_X86_64_PC32	.text+0xae87d6
28f0     28f0:	e9 00 00 00 00       	jmp    28f5 <.altinstr_replacement+0x28f5>	28f1: R_X86_64_PC32	.text+0xae8d26
28f5     28f5:	9c                   	pushf
28f6     28f6:	58                   	pop    %rax
28f7     28f7:	fa                   	cli
28f8     28f8:	9c                   	pushf
28f9     28f9:	58                   	pop    %rax
28fa     28fa:	fb                   	sti
28fb     28fb:	e9 00 00 00 00       	jmp    2900 <.altinstr_replacement+0x2900>	28fc: R_X86_64_PC32	.text+0xaeb65d
2900     2900:	e9 00 00 00 00       	jmp    2905 <.altinstr_replacement+0x2905>	2901: R_X86_64_PC32	.text+0xaeb67c
2905     2905:	9c                   	pushf
2906     2906:	58                   	pop    %rax
2907     2907:	fa                   	cli
2908     2908:	9c                   	pushf
2909     2909:	58                   	pop    %rax
290a     290a:	fb                   	sti
290b     290b:	e9 00 00 00 00       	jmp    2910 <.altinstr_replacement+0x2910>	290c: R_X86_64_PC32	.text+0xaeccee
2910     2910:	e9 00 00 00 00       	jmp    2915 <.altinstr_replacement+0x2915>	2911: R_X86_64_PC32	.text+0xaecfd0
2915     2915:	9c                   	pushf
2916     2916:	58                   	pop    %rax
2917     2917:	fa                   	cli
2918     2918:	9c                   	pushf
2919     2919:	58                   	pop    %rax
291a     291a:	fb                   	sti
291b     291b:	e8 00 00 00 00       	call   2920 <.altinstr_replacement+0x2920>	291c: R_X86_64_PLT32	clear_page_rep-0x4
2920     2920:	e8 00 00 00 00       	call   2925 <.altinstr_replacement+0x2925>	2921: R_X86_64_PLT32	clear_page_erms-0x4
2925     2925:	e9 00 00 00 00       	jmp    292a <.altinstr_replacement+0x292a>	2926: R_X86_64_PC32	.text+0xaf471d
292a     292a:	e9 00 00 00 00       	jmp    292f <.altinstr_replacement+0x292f>	292b: R_X86_64_PC32	.text+0xaf550a
292f     292f:	e9 00 00 00 00       	jmp    2934 <.altinstr_replacement+0x2934>	2930: R_X86_64_PC32	.text+0xaf719a
2934     2934:	e9 00 00 00 00       	jmp    2939 <.altinstr_replacement+0x2939>	2935: R_X86_64_PC32	.text+0xaf7057
2939     2939:	e9 00 00 00 00       	jmp    293e <.altinstr_replacement+0x293e>	293a: R_X86_64_PC32	.text+0xaf7825
293e     293e:	e9 00 00 00 00       	jmp    2943 <.altinstr_replacement+0x2943>	293f: R_X86_64_PC32	.text+0xaf7aa9
2943     2943:	e9 00 00 00 00       	jmp    2948 <.altinstr_replacement+0x2948>	2944: R_X86_64_PC32	.text+0xaf864b
2948     2948:	e9 00 00 00 00       	jmp    294d <.altinstr_replacement+0x294d>	2949: R_X86_64_PC32	.text+0xaf87c5
294d     294d:	e9 00 00 00 00       	jmp    2952 <.altinstr_replacement+0x2952>	294e: R_X86_64_PC32	.text+0xaf96e5
2952     2952:	e9 00 00 00 00       	jmp    2957 <.altinstr_replacement+0x2957>	2953: R_X86_64_PC32	.text+0xaf9fd7
2957     2957:	e9 00 00 00 00       	jmp    295c <.altinstr_replacement+0x295c>	2958: R_X86_64_PC32	.text+0xafa617
295c     295c:	48 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbp
2966     2966:	48 89 f8             	mov    %rdi,%rax
2969     2969:	48 89 f8             	mov    %rdi,%rax
296c     296c:	48 89 f8             	mov    %rdi,%rax
296f     296f:	48 89 f8             	mov    %rdi,%rax
2972     2972:	48 89 f8             	mov    %rdi,%rax
2975     2975:	48 89 f8             	mov    %rdi,%rax
2978     2978:	48 89 f8             	mov    %rdi,%rax
297b     297b:	48 89 f8             	mov    %rdi,%rax
297e     297e:	48 89 f8             	mov    %rdi,%rax
2981     2981:	48 89 f8             	mov    %rdi,%rax
2984     2984:	48 89 f8             	mov    %rdi,%rax
2987     2987:	48 89 f8             	mov    %rdi,%rax
298a     298a:	48 89 f8             	mov    %rdi,%rax
298d     298d:	48 89 f8             	mov    %rdi,%rax
2990     2990:	48 89 f8             	mov    %rdi,%rax
2993     2993:	48 89 f8             	mov    %rdi,%rax
2996     2996:	48 89 f8             	mov    %rdi,%rax
2999     2999:	48 89 f8             	mov    %rdi,%rax
299c     299c:	48 89 f8             	mov    %rdi,%rax
299f     299f:	48 89 f8             	mov    %rdi,%rax
29a2     29a2:	48 89 f8             	mov    %rdi,%rax
29a5     29a5:	48 89 f8             	mov    %rdi,%rax
29a8     29a8:	48 89 f8             	mov    %rdi,%rax
29ab     29ab:	48 89 f8             	mov    %rdi,%rax
29ae     29ae:	48 89 f8             	mov    %rdi,%rax
29b1     29b1:	48 89 f8             	mov    %rdi,%rax
29b4     29b4:	48 89 f8             	mov    %rdi,%rax
29b7     29b7:	48 89 f8             	mov    %rdi,%rax
29ba     29ba:	48 89 f8             	mov    %rdi,%rax
29bd     29bd:	48 89 f8             	mov    %rdi,%rax
29c0     29c0:	48 89 f8             	mov    %rdi,%rax
29c3     29c3:	48 89 f8             	mov    %rdi,%rax
29c6     29c6:	48 89 f8             	mov    %rdi,%rax
29c9     29c9:	48 89 f8             	mov    %rdi,%rax
29cc     29cc:	48 89 f8             	mov    %rdi,%rax
29cf     29cf:	48 89 f8             	mov    %rdi,%rax
29d2     29d2:	e9 00 00 00 00       	jmp    29d7 <.altinstr_replacement+0x29d7>	29d3: R_X86_64_PC32	.text+0xb1a990
29d7     29d7:	e9 00 00 00 00       	jmp    29dc <.altinstr_replacement+0x29dc>	29d8: R_X86_64_PC32	.text+0xb1a9f7
29dc     29dc:	e9 00 00 00 00       	jmp    29e1 <.altinstr_replacement+0x29e1>	29dd: R_X86_64_PC32	.text+0xb1ad9f
29e1     29e1:	48 89 f8             	mov    %rdi,%rax
29e4     29e4:	48 89 f8             	mov    %rdi,%rax
29e7     29e7:	48 89 f8             	mov    %rdi,%rax
29ea     29ea:	48 89 f8             	mov    %rdi,%rax
29ed     29ed:	e9 00 00 00 00       	jmp    29f2 <.altinstr_replacement+0x29f2>	29ee: R_X86_64_PC32	.init.text+0xe5062
29f2     29f2:	9c                   	pushf
29f3     29f3:	58                   	pop    %rax
29f4     29f4:	fa                   	cli
29f5     29f5:	9c                   	pushf
29f6     29f6:	58                   	pop    %rax
29f7     29f7:	fb                   	sti
29f8     29f8:	48 89 f8             	mov    %rdi,%rax
29fb     29fb:	e9 00 00 00 00       	jmp    2a00 <.altinstr_replacement+0x2a00>	29fc: R_X86_64_PC32	.text+0xb274de
2a00     2a00:	48 89 f8             	mov    %rdi,%rax
2a03     2a03:	e9 00 00 00 00       	jmp    2a08 <.altinstr_replacement+0x2a08>	2a04: R_X86_64_PC32	.text+0xb27a6f
2a08     2a08:	e9 00 00 00 00       	jmp    2a0d <.altinstr_replacement+0x2a0d>	2a09: R_X86_64_PC32	.text+0xb27ac8
2a0d     2a0d:	9c                   	pushf
2a0e     2a0e:	58                   	pop    %rax
2a0f     2a0f:	fa                   	cli
2a10     2a10:	9c                   	pushf
2a11     2a11:	58                   	pop    %rax
2a12     2a12:	fb                   	sti
2a13     2a13:	48 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbp
2a1d     2a1d:	48 89 f8             	mov    %rdi,%rax
2a20     2a20:	48 89 f8             	mov    %rdi,%rax
2a23     2a23:	48 89 f8             	mov    %rdi,%rax
2a26     2a26:	48 89 f8             	mov    %rdi,%rax
2a29     2a29:	48 89 f8             	mov    %rdi,%rax
2a2c     2a2c:	48 89 f8             	mov    %rdi,%rax
2a2f     2a2f:	48 89 f8             	mov    %rdi,%rax
2a32     2a32:	48 89 f8             	mov    %rdi,%rax
2a35     2a35:	e9 00 00 00 00       	jmp    2a3a <.altinstr_replacement+0x2a3a>	2a36: R_X86_64_PC32	.text+0xb3a587
2a3a     2a3a:	48 89 f8             	mov    %rdi,%rax
2a3d     2a3d:	48 89 f8             	mov    %rdi,%rax
2a40     2a40:	48 89 f8             	mov    %rdi,%rax
2a43     2a43:	48 89 f8             	mov    %rdi,%rax
2a46     2a46:	e9 00 00 00 00       	jmp    2a4b <.altinstr_replacement+0x2a4b>	2a47: R_X86_64_PC32	.text+0xb3b2e1
2a4b     2a4b:	48 89 f8             	mov    %rdi,%rax
2a4e     2a4e:	48 89 f8             	mov    %rdi,%rax
2a51     2a51:	48 89 f8             	mov    %rdi,%rax
2a54     2a54:	48 89 f8             	mov    %rdi,%rax
2a57     2a57:	48 89 f8             	mov    %rdi,%rax
2a5a     2a5a:	48 89 f8             	mov    %rdi,%rax
2a5d     2a5d:	48 89 f8             	mov    %rdi,%rax
2a60     2a60:	48 89 f8             	mov    %rdi,%rax
2a63     2a63:	48 89 f8             	mov    %rdi,%rax
2a66     2a66:	48 89 f8             	mov    %rdi,%rax
2a69     2a69:	48 89 f8             	mov    %rdi,%rax
2a6c     2a6c:	48 89 f8             	mov    %rdi,%rax
2a6f     2a6f:	48 89 f8             	mov    %rdi,%rax
2a72     2a72:	48 89 f8             	mov    %rdi,%rax
2a75     2a75:	48 89 f8             	mov    %rdi,%rax
2a78     2a78:	e9 00 00 00 00       	jmp    2a7d <.altinstr_replacement+0x2a7d>	2a79: R_X86_64_PC32	.text+0xb4511e
2a7d     2a7d:	48 89 f8             	mov    %rdi,%rax
2a80     2a80:	48 89 f8             	mov    %rdi,%rax
2a83     2a83:	48 89 f8             	mov    %rdi,%rax
2a86     2a86:	48 89 f8             	mov    %rdi,%rax
2a89     2a89:	48 89 f8             	mov    %rdi,%rax
2a8c     2a8c:	48 89 f8             	mov    %rdi,%rax
2a8f     2a8f:	48 89 f8             	mov    %rdi,%rax
2a92     2a92:	48 89 f8             	mov    %rdi,%rax
2a95     2a95:	48 89 f8             	mov    %rdi,%rax
2a98     2a98:	48 89 f8             	mov    %rdi,%rax
2a9b     2a9b:	48 89 f8             	mov    %rdi,%rax
2a9e     2a9e:	48 89 f8             	mov    %rdi,%rax
2aa1     2aa1:	48 89 f8             	mov    %rdi,%rax
2aa4     2aa4:	48 89 f8             	mov    %rdi,%rax
2aa7     2aa7:	48 89 f8             	mov    %rdi,%rax
2aaa     2aaa:	48 89 f8             	mov    %rdi,%rax
2aad     2aad:	48 89 f8             	mov    %rdi,%rax
2ab0     2ab0:	48 89 f8             	mov    %rdi,%rax
2ab3     2ab3:	48 89 f8             	mov    %rdi,%rax
2ab6     2ab6:	48 89 f8             	mov    %rdi,%rax
2ab9     2ab9:	48 89 f8             	mov    %rdi,%rax
2abc     2abc:	48 89 f8             	mov    %rdi,%rax
2abf     2abf:	48 89 f8             	mov    %rdi,%rax
2ac2     2ac2:	48 89 f8             	mov    %rdi,%rax
2ac5     2ac5:	49 bf 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r15
2acf     2acf:	e9 00 00 00 00       	jmp    2ad4 <.altinstr_replacement+0x2ad4>	2ad0: R_X86_64_PC32	.text+0xb53dfe
2ad4     2ad4:	e9 00 00 00 00       	jmp    2ad9 <.altinstr_replacement+0x2ad9>	2ad5: R_X86_64_PC32	.meminit.text+0xb51a
2ad9     2ad9:	e9 00 00 00 00       	jmp    2ade <.altinstr_replacement+0x2ade>	2ada: R_X86_64_PC32	.init.text+0xea659
2ade     2ade:	e9 00 00 00 00       	jmp    2ae3 <.altinstr_replacement+0x2ae3>	2adf: R_X86_64_PC32	.init.text+0xea6a1
2ae3     2ae3:	e9 00 00 00 00       	jmp    2ae8 <.altinstr_replacement+0x2ae8>	2ae4: R_X86_64_PC32	.init.text+0xeadb7
2ae8     2ae8:	e9 00 00 00 00       	jmp    2aed <.altinstr_replacement+0x2aed>	2ae9: R_X86_64_PC32	.text+0xb54122
2aed     2aed:	e9 00 00 00 00       	jmp    2af2 <.altinstr_replacement+0x2af2>	2aee: R_X86_64_PC32	.text+0xb54117
2af2     2af2:	e9 00 00 00 00       	jmp    2af7 <.altinstr_replacement+0x2af7>	2af3: R_X86_64_PC32	.text+0xb5452f
2af7     2af7:	e9 00 00 00 00       	jmp    2afc <.altinstr_replacement+0x2afc>	2af8: R_X86_64_PC32	.text+0xb54539
2afc     2afc:	e9 00 00 00 00       	jmp    2b01 <.altinstr_replacement+0x2b01>	2afd: R_X86_64_PC32	.text+0xb546af
2b01     2b01:	e9 00 00 00 00       	jmp    2b06 <.altinstr_replacement+0x2b06>	2b02: R_X86_64_PC32	.text+0xb546b9
2b06     2b06:	48 89 f8             	mov    %rdi,%rax
2b09     2b09:	48 89 f8             	mov    %rdi,%rax
2b0c     2b0c:	48 89 f8             	mov    %rdi,%rax
2b0f     2b0f:	48 89 f8             	mov    %rdi,%rax
2b12     2b12:	e9 00 00 00 00       	jmp    2b17 <.altinstr_replacement+0x2b17>	2b13: R_X86_64_PC32	.text.unlikely+0x79aed
2b17     2b17:	48 89 f8             	mov    %rdi,%rax
2b1a     2b1a:	48 89 f8             	mov    %rdi,%rax
2b1d     2b1d:	e9 00 00 00 00       	jmp    2b22 <.altinstr_replacement+0x2b22>	2b1e: R_X86_64_PC32	.text.unlikely+0x79d8f
2b22     2b22:	e9 00 00 00 00       	jmp    2b27 <.altinstr_replacement+0x2b27>	2b23: R_X86_64_PC32	.text.unlikely+0x79cf2
2b27     2b27:	48 89 f8             	mov    %rdi,%rax
2b2a     2b2a:	48 89 f8             	mov    %rdi,%rax
2b2d     2b2d:	48 89 f8             	mov    %rdi,%rax
2b30     2b30:	48 89 f8             	mov    %rdi,%rax
2b33     2b33:	e9 00 00 00 00       	jmp    2b38 <.altinstr_replacement+0x2b38>	2b34: R_X86_64_PC32	.meminit.text+0xd3d0
2b38     2b38:	48 89 f8             	mov    %rdi,%rax
2b3b     2b3b:	48 89 f8             	mov    %rdi,%rax
2b3e     2b3e:	48 89 f8             	mov    %rdi,%rax
2b41     2b41:	48 89 f8             	mov    %rdi,%rax
2b44     2b44:	48 89 f8             	mov    %rdi,%rax
2b47     2b47:	48 89 f8             	mov    %rdi,%rax
2b4a     2b4a:	9c                   	pushf
2b4b     2b4b:	58                   	pop    %rax
2b4c     2b4c:	fa                   	cli
2b4d     2b4d:	9c                   	pushf
2b4e     2b4e:	58                   	pop    %rax
2b4f     2b4f:	fb                   	sti
2b50     2b50:	9c                   	pushf
2b51     2b51:	58                   	pop    %rax
2b52     2b52:	fa                   	cli
2b53     2b53:	9c                   	pushf
2b54     2b54:	58                   	pop    %rax
2b55     2b55:	fb                   	sti
2b56     2b56:	9c                   	pushf
2b57     2b57:	58                   	pop    %rax
2b58     2b58:	fa                   	cli
2b59     2b59:	9c                   	pushf
2b5a     2b5a:	58                   	pop    %rax
2b5b     2b5b:	fb                   	sti
2b5c     2b5c:	9c                   	pushf
2b5d     2b5d:	58                   	pop    %rax
2b5e     2b5e:	fb                   	sti
2b5f     2b5f:	65 48 0f c7 0f       	cmpxchg16b %gs:(%rdi)
2b64     2b64:	0f 94 c0             	sete   %al
2b67     2b67:	9c                   	pushf
2b68     2b68:	58                   	pop    %rax
2b69     2b69:	fa                   	cli
2b6a     2b6a:	9c                   	pushf
2b6b     2b6b:	58                   	pop    %rax
2b6c     2b6c:	fb                   	sti
2b6d     2b6d:	9c                   	pushf
2b6e     2b6e:	58                   	pop    %rax
2b6f     2b6f:	fa                   	cli
2b70     2b70:	9c                   	pushf
2b71     2b71:	58                   	pop    %rax
2b72     2b72:	fb                   	sti
2b73     2b73:	9c                   	pushf
2b74     2b74:	58                   	pop    %rax
2b75     2b75:	fa                   	cli
2b76     2b76:	9c                   	pushf
2b77     2b77:	58                   	pop    %rax
2b78     2b78:	fb                   	sti
2b79     2b79:	9c                   	pushf
2b7a     2b7a:	58                   	pop    %rax
2b7b     2b7b:	fa                   	cli
2b7c     2b7c:	9c                   	pushf
2b7d     2b7d:	58                   	pop    %rax
2b7e     2b7e:	fb                   	sti
2b7f     2b7f:	9c                   	pushf
2b80     2b80:	58                   	pop    %rax
2b81     2b81:	fa                   	cli
2b82     2b82:	9c                   	pushf
2b83     2b83:	58                   	pop    %rax
2b84     2b84:	fb                   	sti
2b85     2b85:	9c                   	pushf
2b86     2b86:	58                   	pop    %rax
2b87     2b87:	fa                   	cli
2b88     2b88:	9c                   	pushf
2b89     2b89:	58                   	pop    %rax
2b8a     2b8a:	fb                   	sti
2b8b     2b8b:	9c                   	pushf
2b8c     2b8c:	58                   	pop    %rax
2b8d     2b8d:	9c                   	pushf
2b8e     2b8e:	58                   	pop    %rax
2b8f     2b8f:	fb                   	sti
2b90     2b90:	9c                   	pushf
2b91     2b91:	58                   	pop    %rax
2b92     2b92:	fb                   	sti
2b93     2b93:	9c                   	pushf
2b94     2b94:	58                   	pop    %rax
2b95     2b95:	fa                   	cli
2b96     2b96:	9c                   	pushf
2b97     2b97:	58                   	pop    %rax
2b98     2b98:	fb                   	sti
2b99     2b99:	9c                   	pushf
2b9a     2b9a:	58                   	pop    %rax
2b9b     2b9b:	9c                   	pushf
2b9c     2b9c:	58                   	pop    %rax
2b9d     2b9d:	fb                   	sti
2b9e     2b9e:	65 48 0f c7 0f       	cmpxchg16b %gs:(%rdi)
2ba3     2ba3:	0f 94 c0             	sete   %al
2ba6     2ba6:	0f 0d 0c 03          	prefetchw (%rbx,%rax,1)
2baa     2baa:	65 48 0f c7 0f       	cmpxchg16b %gs:(%rdi)
2baf     2baf:	0f 94 c0             	sete   %al
2bb2     2bb2:	0f 0d 0c 03          	prefetchw (%rbx,%rax,1)
2bb6     2bb6:	65 48 0f c7 0f       	cmpxchg16b %gs:(%rdi)
2bbb     2bbb:	0f 94 c0             	sete   %al
2bbe     2bbe:	0f 0d 0c 03          	prefetchw (%rbx,%rax,1)
2bc2     2bc2:	65 48 0f c7 0f       	cmpxchg16b %gs:(%rdi)
2bc7     2bc7:	0f 94 c0             	sete   %al
2bca     2bca:	0f 0d 0c 03          	prefetchw (%rbx,%rax,1)
2bce     2bce:	65 48 0f c7 0f       	cmpxchg16b %gs:(%rdi)
2bd3     2bd3:	0f 94 c0             	sete   %al
2bd6     2bd6:	0f 0d 0c 03          	prefetchw (%rbx,%rax,1)
2bda     2bda:	65 48 0f c7 0f       	cmpxchg16b %gs:(%rdi)
2bdf     2bdf:	0f 94 c0             	sete   %al
2be2     2be2:	0f 0d 0c 03          	prefetchw (%rbx,%rax,1)
2be6     2be6:	65 48 0f c7 0f       	cmpxchg16b %gs:(%rdi)
2beb     2beb:	0f 94 c0             	sete   %al
2bee     2bee:	0f 0d 0c 03          	prefetchw (%rbx,%rax,1)
2bf2     2bf2:	65 48 0f c7 0f       	cmpxchg16b %gs:(%rdi)
2bf7     2bf7:	0f 94 c0             	sete   %al
2bfa     2bfa:	0f 0d 0c 03          	prefetchw (%rbx,%rax,1)
2bfe     2bfe:	65 48 0f c7 0f       	cmpxchg16b %gs:(%rdi)
2c03     2c03:	0f 94 c0             	sete   %al
2c06     2c06:	0f 0d 0c 03          	prefetchw (%rbx,%rax,1)
2c0a     2c0a:	65 48 0f c7 0f       	cmpxchg16b %gs:(%rdi)
2c0f     2c0f:	0f 94 c0             	sete   %al
2c12     2c12:	65 48 0f c7 0f       	cmpxchg16b %gs:(%rdi)
2c17     2c17:	0f 94 c0             	sete   %al
2c1a     2c1a:	9c                   	pushf
2c1b     2c1b:	58                   	pop    %rax
2c1c     2c1c:	fa                   	cli
2c1d     2c1d:	fb                   	sti
2c1e     2c1e:	fb                   	sti
2c1f     2c1f:	9c                   	pushf
2c20     2c20:	58                   	pop    %rax
2c21     2c21:	fa                   	cli
2c22     2c22:	9c                   	pushf
2c23     2c23:	58                   	pop    %rax
2c24     2c24:	9c                   	pushf
2c25     2c25:	58                   	pop    %rax
2c26     2c26:	65 48 0f c7 0f       	cmpxchg16b %gs:(%rdi)
2c2b     2c2b:	0f 94 c0             	sete   %al
2c2e     2c2e:	e9 00 00 00 00       	jmp    2c33 <.altinstr_replacement+0x2c33>	2c2f: R_X86_64_PC32	.text.unlikely+0x7b792
2c33     2c33:	9c                   	pushf
2c34     2c34:	8f 04 24             	pop    (%rsp)
2c37     2c37:	0f 01 ca             	clac
2c3a     2c3a:	ff 34 24             	push   (%rsp)
2c3d     2c3d:	9d                   	popf
2c3e     2c3e:	48 89 f8             	mov    %rdi,%rax
2c41     2c41:	9c                   	pushf
2c42     2c42:	58                   	pop    %rax
2c43     2c43:	fa                   	cli
2c44     2c44:	9c                   	pushf
2c45     2c45:	58                   	pop    %rax
2c46     2c46:	fb                   	sti
2c47     2c47:	48 89 f8             	mov    %rdi,%rax
2c4a     2c4a:	48 89 f8             	mov    %rdi,%rax
2c4d     2c4d:	48 89 f8             	mov    %rdi,%rax
2c50     2c50:	48 89 f8             	mov    %rdi,%rax
2c53     2c53:	48 89 f8             	mov    %rdi,%rax
2c56     2c56:	48 89 f8             	mov    %rdi,%rax
2c59     2c59:	48 89 f8             	mov    %rdi,%rax
2c5c     2c5c:	48 89 f8             	mov    %rdi,%rax
2c5f     2c5f:	48 89 f8             	mov    %rdi,%rax
2c62     2c62:	48 89 f8             	mov    %rdi,%rax
2c65     2c65:	48 89 f8             	mov    %rdi,%rax
2c68     2c68:	48 89 f8             	mov    %rdi,%rax
2c6b     2c6b:	48 89 f8             	mov    %rdi,%rax
2c6e     2c6e:	48 89 f8             	mov    %rdi,%rax
2c71     2c71:	48 89 f8             	mov    %rdi,%rax
2c74     2c74:	48 89 f8             	mov    %rdi,%rax
2c77     2c77:	48 89 f8             	mov    %rdi,%rax
2c7a     2c7a:	48 89 f8             	mov    %rdi,%rax
2c7d     2c7d:	e9 00 00 00 00       	jmp    2c82 <.altinstr_replacement+0x2c82>	2c7e: R_X86_64_PC32	.text+0xb79242
2c82     2c82:	48 89 f8             	mov    %rdi,%rax
2c85     2c85:	48 89 f8             	mov    %rdi,%rax
2c88     2c88:	48 89 f8             	mov    %rdi,%rax
2c8b     2c8b:	48 89 f8             	mov    %rdi,%rax
2c8e     2c8e:	e9 00 00 00 00       	jmp    2c93 <.altinstr_replacement+0x2c93>	2c8f: R_X86_64_PC32	.text+0xb792fc
2c93     2c93:	e9 00 00 00 00       	jmp    2c98 <.altinstr_replacement+0x2c98>	2c94: R_X86_64_PC32	.text+0xb79319
2c98     2c98:	48 89 f8             	mov    %rdi,%rax
2c9b     2c9b:	48 89 f8             	mov    %rdi,%rax
2c9e     2c9e:	48 89 f8             	mov    %rdi,%rax
2ca1     2ca1:	48 89 f8             	mov    %rdi,%rax
2ca4     2ca4:	48 89 f8             	mov    %rdi,%rax
2ca7     2ca7:	48 89 f8             	mov    %rdi,%rax
2caa     2caa:	48 89 f8             	mov    %rdi,%rax
2cad     2cad:	e9 00 00 00 00       	jmp    2cb2 <.altinstr_replacement+0x2cb2>	2cae: R_X86_64_PC32	.text+0xb79685
2cb2     2cb2:	e9 00 00 00 00       	jmp    2cb7 <.altinstr_replacement+0x2cb7>	2cb3: R_X86_64_PC32	.text+0xb79622
2cb7     2cb7:	e9 00 00 00 00       	jmp    2cbc <.altinstr_replacement+0x2cbc>	2cb8: R_X86_64_PC32	.text+0xb796c0
2cbc     2cbc:	e9 00 00 00 00       	jmp    2cc1 <.altinstr_replacement+0x2cc1>	2cbd: R_X86_64_PC32	.ref.text+0x62f3
2cc1     2cc1:	e9 00 00 00 00       	jmp    2cc6 <.altinstr_replacement+0x2cc6>	2cc2: R_X86_64_PC32	.ref.text+0x62df
2cc6     2cc6:	48 89 f8             	mov    %rdi,%rax
2cc9     2cc9:	48 89 f8             	mov    %rdi,%rax
2ccc     2ccc:	e9 00 00 00 00       	jmp    2cd1 <.altinstr_replacement+0x2cd1>	2ccd: R_X86_64_PC32	.text+0xb79813
2cd1     2cd1:	48 89 f8             	mov    %rdi,%rax
2cd4     2cd4:	e9 00 00 00 00       	jmp    2cd9 <.altinstr_replacement+0x2cd9>	2cd5: R_X86_64_PC32	.text+0xb797e5
2cd9     2cd9:	e9 00 00 00 00       	jmp    2cde <.altinstr_replacement+0x2cde>	2cda: R_X86_64_PC32	.text+0xb7991d
2cde     2cde:	e9 00 00 00 00       	jmp    2ce3 <.altinstr_replacement+0x2ce3>	2cdf: R_X86_64_PC32	.text+0xb79c1b
2ce3     2ce3:	e9 00 00 00 00       	jmp    2ce8 <.altinstr_replacement+0x2ce8>	2ce4: R_X86_64_PC32	.text+0xb79c9b
2ce8     2ce8:	e9 00 00 00 00       	jmp    2ced <.altinstr_replacement+0x2ced>	2ce9: R_X86_64_PC32	.text+0xb79d1b
2ced     2ced:	e9 00 00 00 00       	jmp    2cf2 <.altinstr_replacement+0x2cf2>	2cee: R_X86_64_PC32	.text+0xb79ddb
2cf2     2cf2:	e9 00 00 00 00       	jmp    2cf7 <.altinstr_replacement+0x2cf7>	2cf3: R_X86_64_PC32	.text+0xb79e9b
2cf7     2cf7:	e9 00 00 00 00       	jmp    2cfc <.altinstr_replacement+0x2cfc>	2cf8: R_X86_64_PC32	.text+0xb79f5b
2cfc     2cfc:	e9 00 00 00 00       	jmp    2d01 <.altinstr_replacement+0x2d01>	2cfd: R_X86_64_PC32	.text+0xb7a01b
2d01     2d01:	e9 00 00 00 00       	jmp    2d06 <.altinstr_replacement+0x2d06>	2d02: R_X86_64_PC32	.text+0xb7a11b
2d06     2d06:	e9 00 00 00 00       	jmp    2d0b <.altinstr_replacement+0x2d0b>	2d07: R_X86_64_PC32	.text+0xb7a21b
2d0b     2d0b:	e9 00 00 00 00       	jmp    2d10 <.altinstr_replacement+0x2d10>	2d0c: R_X86_64_PC32	.text+0xb7a2db
2d10     2d10:	e9 00 00 00 00       	jmp    2d15 <.altinstr_replacement+0x2d15>	2d11: R_X86_64_PC32	.text+0xb7a65d
2d15     2d15:	e9 00 00 00 00       	jmp    2d1a <.altinstr_replacement+0x2d1a>	2d16: R_X86_64_PC32	.text+0xb7b00e
2d1a     2d1a:	e9 00 00 00 00       	jmp    2d1f <.altinstr_replacement+0x2d1f>	2d1b: R_X86_64_PC32	.text+0xb7b0e4
2d1f     2d1f:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
2d29     2d29:	e9 00 00 00 00       	jmp    2d2e <.altinstr_replacement+0x2d2e>	2d2a: R_X86_64_PC32	.text.unlikely+0x7bff7
2d2e     2d2e:	48 89 f8             	mov    %rdi,%rax
2d31     2d31:	e9 00 00 00 00       	jmp    2d36 <.altinstr_replacement+0x2d36>	2d32: R_X86_64_PC32	.text.unlikely+0x7c045
2d36     2d36:	48 89 f8             	mov    %rdi,%rax
2d39     2d39:	48 89 f8             	mov    %rdi,%rax
2d3c     2d3c:	48 89 f8             	mov    %rdi,%rax
2d3f     2d3f:	48 89 f8             	mov    %rdi,%rax
2d42     2d42:	48 89 f8             	mov    %rdi,%rax
2d45     2d45:	9c                   	pushf
2d46     2d46:	58                   	pop    %rax
2d47     2d47:	fa                   	cli
2d48     2d48:	9c                   	pushf
2d49     2d49:	58                   	pop    %rax
2d4a     2d4a:	fb                   	sti
2d4b     2d4b:	9c                   	pushf
2d4c     2d4c:	58                   	pop    %rax
2d4d     2d4d:	fb                   	sti
2d4e     2d4e:	48 89 f8             	mov    %rdi,%rax
2d51     2d51:	48 89 f8             	mov    %rdi,%rax
2d54     2d54:	48 89 f8             	mov    %rdi,%rax
2d57     2d57:	48 89 f8             	mov    %rdi,%rax
2d5a     2d5a:	9c                   	pushf
2d5b     2d5b:	58                   	pop    %rax
2d5c     2d5c:	fa                   	cli
2d5d     2d5d:	9c                   	pushf
2d5e     2d5e:	58                   	pop    %rax
2d5f     2d5f:	fb                   	sti
2d60     2d60:	48 89 f8             	mov    %rdi,%rax
2d63     2d63:	48 89 f8             	mov    %rdi,%rax
2d66     2d66:	48 89 f8             	mov    %rdi,%rax
2d69     2d69:	e9 00 00 00 00       	jmp    2d6e <.altinstr_replacement+0x2d6e>	2d6a: R_X86_64_PC32	.text+0xb8e4fb
2d6e     2d6e:	e9 00 00 00 00       	jmp    2d73 <.altinstr_replacement+0x2d73>	2d6f: R_X86_64_PC32	.text+0xb8e6ce
2d73     2d73:	fb                   	sti
2d74     2d74:	48 89 f8             	mov    %rdi,%rax
2d77     2d77:	48 89 f8             	mov    %rdi,%rax
2d7a     2d7a:	48 89 f8             	mov    %rdi,%rax
2d7d     2d7d:	48 89 f8             	mov    %rdi,%rax
2d80     2d80:	48 89 f8             	mov    %rdi,%rax
2d83     2d83:	48 89 f8             	mov    %rdi,%rax
2d86     2d86:	e9 00 00 00 00       	jmp    2d8b <.altinstr_replacement+0x2d8b>	2d87: R_X86_64_PC32	.text+0xb9a079
2d8b     2d8b:	e9 00 00 00 00       	jmp    2d90 <.altinstr_replacement+0x2d90>	2d8c: R_X86_64_PC32	.text+0xb9a119
2d90     2d90:	48 89 f8             	mov    %rdi,%rax
2d93     2d93:	48 89 f8             	mov    %rdi,%rax
2d96     2d96:	e9 00 00 00 00       	jmp    2d9b <.altinstr_replacement+0x2d9b>	2d97: R_X86_64_PC32	.text+0xb9d8b3
2d9b     2d9b:	e9 00 00 00 00       	jmp    2da0 <.altinstr_replacement+0x2da0>	2d9c: R_X86_64_PC32	.text+0xb9d90c
2da0     2da0:	48 89 f8             	mov    %rdi,%rax
2da3     2da3:	48 89 f8             	mov    %rdi,%rax
2da6     2da6:	48 89 f8             	mov    %rdi,%rax
2da9     2da9:	48 89 f8             	mov    %rdi,%rax
2dac     2dac:	48 89 f8             	mov    %rdi,%rax
2daf     2daf:	48 89 f8             	mov    %rdi,%rax
2db2     2db2:	48 89 f8             	mov    %rdi,%rax
2db5     2db5:	48 89 f8             	mov    %rdi,%rax
2db8     2db8:	48 89 f8             	mov    %rdi,%rax
2dbb     2dbb:	48 89 f8             	mov    %rdi,%rax
2dbe     2dbe:	48 89 f8             	mov    %rdi,%rax
2dc1     2dc1:	e9 00 00 00 00       	jmp    2dc6 <.altinstr_replacement+0x2dc6>	2dc2: R_X86_64_PC32	.text+0xb9fee4
2dc6     2dc6:	e9 00 00 00 00       	jmp    2dcb <.altinstr_replacement+0x2dcb>	2dc7: R_X86_64_PC32	.text+0xb9fef3
2dcb     2dcb:	48 89 f8             	mov    %rdi,%rax
2dce     2dce:	48 89 f8             	mov    %rdi,%rax
2dd1     2dd1:	48 89 f8             	mov    %rdi,%rax
2dd4     2dd4:	48 89 f8             	mov    %rdi,%rax
2dd7     2dd7:	48 89 f8             	mov    %rdi,%rax
2dda     2dda:	48 89 f8             	mov    %rdi,%rax
2ddd     2ddd:	48 89 f8             	mov    %rdi,%rax
2de0     2de0:	48 89 f8             	mov    %rdi,%rax
2de3     2de3:	48 89 f8             	mov    %rdi,%rax
2de6     2de6:	48 89 f8             	mov    %rdi,%rax
2de9     2de9:	48 89 f8             	mov    %rdi,%rax
2dec     2dec:	e9 00 00 00 00       	jmp    2df1 <.altinstr_replacement+0x2df1>	2ded: R_X86_64_PC32	.text+0xba3aaf
2df1     2df1:	e9 00 00 00 00       	jmp    2df6 <.altinstr_replacement+0x2df6>	2df2: R_X86_64_PC32	.text+0xba3b08
2df6     2df6:	9c                   	pushf
2df7     2df7:	58                   	pop    %rax
2df8     2df8:	fa                   	cli
2df9     2df9:	9c                   	pushf
2dfa     2dfa:	58                   	pop    %rax
2dfb     2dfb:	fb                   	sti
2dfc     2dfc:	9c                   	pushf
2dfd     2dfd:	58                   	pop    %rax
2dfe     2dfe:	fa                   	cli
2dff     2dff:	9c                   	pushf
2e00     2e00:	58                   	pop    %rax
2e01     2e01:	fb                   	sti
2e02     2e02:	e9 00 00 00 00       	jmp    2e07 <.altinstr_replacement+0x2e07>	2e03: R_X86_64_PC32	.text+0xba53ab
2e07     2e07:	e9 00 00 00 00       	jmp    2e0c <.altinstr_replacement+0x2e0c>	2e08: R_X86_64_PC32	.text+0xba54eb
2e0c     2e0c:	48 89 f8             	mov    %rdi,%rax
2e0f     2e0f:	48 89 f8             	mov    %rdi,%rax
2e12     2e12:	48 89 f8             	mov    %rdi,%rax
2e15     2e15:	48 89 f8             	mov    %rdi,%rax
2e18     2e18:	48 89 f8             	mov    %rdi,%rax
2e1b     2e1b:	48 89 f8             	mov    %rdi,%rax
2e1e     2e1e:	48 89 f8             	mov    %rdi,%rax
2e21     2e21:	48 89 f8             	mov    %rdi,%rax
2e24     2e24:	48 89 f8             	mov    %rdi,%rax
2e27     2e27:	48 89 f8             	mov    %rdi,%rax
2e2a     2e2a:	48 89 f8             	mov    %rdi,%rax
2e2d     2e2d:	48 89 f8             	mov    %rdi,%rax
2e30     2e30:	48 89 f8             	mov    %rdi,%rax
2e33     2e33:	e9 00 00 00 00       	jmp    2e38 <.altinstr_replacement+0x2e38>	2e34: R_X86_64_PC32	.text+0xbac301
2e38     2e38:	e9 00 00 00 00       	jmp    2e3d <.altinstr_replacement+0x2e3d>	2e39: R_X86_64_PC32	.text+0xbac310
2e3d     2e3d:	fb                   	sti
2e3e     2e3e:	48 89 f8             	mov    %rdi,%rax
2e41     2e41:	48 89 f8             	mov    %rdi,%rax
2e44     2e44:	48 89 f8             	mov    %rdi,%rax
2e47     2e47:	48 89 f8             	mov    %rdi,%rax
2e4a     2e4a:	48 89 f8             	mov    %rdi,%rax
2e4d     2e4d:	48 89 f8             	mov    %rdi,%rax
2e50     2e50:	48 89 f8             	mov    %rdi,%rax
2e53     2e53:	48 89 f8             	mov    %rdi,%rax
2e56     2e56:	48 89 f8             	mov    %rdi,%rax
2e59     2e59:	48 89 f8             	mov    %rdi,%rax
2e5c     2e5c:	48 89 f8             	mov    %rdi,%rax
2e5f     2e5f:	48 89 f8             	mov    %rdi,%rax
2e62     2e62:	48 89 f8             	mov    %rdi,%rax
2e65     2e65:	48 89 f8             	mov    %rdi,%rax
2e68     2e68:	48 89 f8             	mov    %rdi,%rax
2e6b     2e6b:	48 89 f8             	mov    %rdi,%rax
2e6e     2e6e:	48 89 f8             	mov    %rdi,%rax
2e71     2e71:	48 89 f8             	mov    %rdi,%rax
2e74     2e74:	48 89 f8             	mov    %rdi,%rax
2e77     2e77:	48 89 f8             	mov    %rdi,%rax
2e7a     2e7a:	9c                   	pushf
2e7b     2e7b:	58                   	pop    %rax
2e7c     2e7c:	fa                   	cli
2e7d     2e7d:	fb                   	sti
2e7e     2e7e:	48 89 f8             	mov    %rdi,%rax
2e81     2e81:	e9 00 00 00 00       	jmp    2e86 <.altinstr_replacement+0x2e86>	2e82: R_X86_64_PC32	.text+0xbbb5d2
2e86     2e86:	e9 00 00 00 00       	jmp    2e8b <.altinstr_replacement+0x2e8b>	2e87: R_X86_64_PC32	.text+0xbbb5e6
2e8b     2e8b:	e9 00 00 00 00       	jmp    2e90 <.altinstr_replacement+0x2e90>	2e8c: R_X86_64_PC32	.text+0xbbbe70
2e90     2e90:	e9 00 00 00 00       	jmp    2e95 <.altinstr_replacement+0x2e95>	2e91: R_X86_64_PC32	.text+0xbbc0e7
2e95     2e95:	9c                   	pushf
2e96     2e96:	58                   	pop    %rax
2e97     2e97:	fa                   	cli
2e98     2e98:	9c                   	pushf
2e99     2e99:	58                   	pop    %rax
2e9a     2e9a:	fb                   	sti
2e9b     2e9b:	9c                   	pushf
2e9c     2e9c:	58                   	pop    %rax
2e9d     2e9d:	fa                   	cli
2e9e     2e9e:	9c                   	pushf
2e9f     2e9f:	58                   	pop    %rax
2ea0     2ea0:	fb                   	sti
2ea1     2ea1:	48 89 f8             	mov    %rdi,%rax
2ea4     2ea4:	48 89 f8             	mov    %rdi,%rax
2ea7     2ea7:	48 89 f8             	mov    %rdi,%rax
2eaa     2eaa:	48 89 f8             	mov    %rdi,%rax
2ead     2ead:	48 89 f8             	mov    %rdi,%rax
2eb0     2eb0:	48 89 f8             	mov    %rdi,%rax
2eb3     2eb3:	48 89 f8             	mov    %rdi,%rax
2eb6     2eb6:	e8 00 00 00 00       	call   2ebb <.altinstr_replacement+0x2ebb>	2eb7: R_X86_64_PLT32	clear_page_rep-0x4
2ebb     2ebb:	e8 00 00 00 00       	call   2ec0 <.altinstr_replacement+0x2ec0>	2ebc: R_X86_64_PLT32	clear_page_erms-0x4
2ec0     2ec0:	48 89 f8             	mov    %rdi,%rax
2ec3     2ec3:	48 89 f8             	mov    %rdi,%rax
2ec6     2ec6:	48 89 f8             	mov    %rdi,%rax
2ec9     2ec9:	48 89 f8             	mov    %rdi,%rax
2ecc     2ecc:	48 89 f8             	mov    %rdi,%rax
2ecf     2ecf:	48 89 f8             	mov    %rdi,%rax
2ed2     2ed2:	48 89 f8             	mov    %rdi,%rax
2ed5     2ed5:	48 89 f8             	mov    %rdi,%rax
2ed8     2ed8:	48 89 f8             	mov    %rdi,%rax
2edb     2edb:	48 89 f8             	mov    %rdi,%rax
2ede     2ede:	48 89 f8             	mov    %rdi,%rax
2ee1     2ee1:	e8 00 00 00 00       	call   2ee6 <.altinstr_replacement+0x2ee6>	2ee2: R_X86_64_PLT32	clear_page_rep-0x4
2ee6     2ee6:	e8 00 00 00 00       	call   2eeb <.altinstr_replacement+0x2eeb>	2ee7: R_X86_64_PLT32	clear_page_erms-0x4
2eeb     2eeb:	e8 00 00 00 00       	call   2ef0 <.altinstr_replacement+0x2ef0>	2eec: R_X86_64_PLT32	clear_page_rep-0x4
2ef0     2ef0:	e8 00 00 00 00       	call   2ef5 <.altinstr_replacement+0x2ef5>	2ef1: R_X86_64_PLT32	clear_page_erms-0x4
2ef5     2ef5:	48 89 f8             	mov    %rdi,%rax
2ef8     2ef8:	48 89 f8             	mov    %rdi,%rax
2efb     2efb:	48 89 f8             	mov    %rdi,%rax
2efe     2efe:	9c                   	pushf
2eff     2eff:	58                   	pop    %rax
2f00     2f00:	9c                   	pushf
2f01     2f01:	58                   	pop    %rax
2f02     2f02:	fa                   	cli
2f03     2f03:	9c                   	pushf
2f04     2f04:	58                   	pop    %rax
2f05     2f05:	fb                   	sti
2f06     2f06:	9c                   	pushf
2f07     2f07:	58                   	pop    %rax
2f08     2f08:	fa                   	cli
2f09     2f09:	9c                   	pushf
2f0a     2f0a:	58                   	pop    %rax
2f0b     2f0b:	fb                   	sti
2f0c     2f0c:	e9 00 00 00 00       	jmp    2f11 <.altinstr_replacement+0x2f11>	2f0d: R_X86_64_PC32	.text+0xbd372a
2f11     2f11:	e9 00 00 00 00       	jmp    2f16 <.altinstr_replacement+0x2f16>	2f12: R_X86_64_PC32	.text+0xbd3760
2f16     2f16:	9c                   	pushf
2f17     2f17:	58                   	pop    %rax
2f18     2f18:	fa                   	cli
2f19     2f19:	9c                   	pushf
2f1a     2f1a:	58                   	pop    %rax
2f1b     2f1b:	fb                   	sti
2f1c     2f1c:	9c                   	pushf
2f1d     2f1d:	58                   	pop    %rax
2f1e     2f1e:	fa                   	cli
2f1f     2f1f:	9c                   	pushf
2f20     2f20:	58                   	pop    %rax
2f21     2f21:	fb                   	sti
2f22     2f22:	48 89 f8             	mov    %rdi,%rax
2f25     2f25:	48 89 f8             	mov    %rdi,%rax
2f28     2f28:	48 89 f8             	mov    %rdi,%rax
2f2b     2f2b:	48 89 f8             	mov    %rdi,%rax
2f2e     2f2e:	9c                   	pushf
2f2f     2f2f:	58                   	pop    %rax
2f30     2f30:	fa                   	cli
2f31     2f31:	9c                   	pushf
2f32     2f32:	58                   	pop    %rax
2f33     2f33:	fb                   	sti
2f34     2f34:	9c                   	pushf
2f35     2f35:	58                   	pop    %rax
2f36     2f36:	9c                   	pushf
2f37     2f37:	58                   	pop    %rax
2f38     2f38:	fa                   	cli
2f39     2f39:	9c                   	pushf
2f3a     2f3a:	58                   	pop    %rax
2f3b     2f3b:	fb                   	sti
2f3c     2f3c:	9c                   	pushf
2f3d     2f3d:	58                   	pop    %rax
2f3e     2f3e:	fa                   	cli
2f3f     2f3f:	9c                   	pushf
2f40     2f40:	58                   	pop    %rax
2f41     2f41:	fb                   	sti
2f42     2f42:	9c                   	pushf
2f43     2f43:	58                   	pop    %rax
2f44     2f44:	fa                   	cli
2f45     2f45:	9c                   	pushf
2f46     2f46:	58                   	pop    %rax
2f47     2f47:	fb                   	sti
2f48     2f48:	9c                   	pushf
2f49     2f49:	58                   	pop    %rax
2f4a     2f4a:	fa                   	cli
2f4b     2f4b:	9c                   	pushf
2f4c     2f4c:	58                   	pop    %rax
2f4d     2f4d:	fb                   	sti
2f4e     2f4e:	9c                   	pushf
2f4f     2f4f:	58                   	pop    %rax
2f50     2f50:	fa                   	cli
2f51     2f51:	9c                   	pushf
2f52     2f52:	58                   	pop    %rax
2f53     2f53:	fb                   	sti
2f54     2f54:	9c                   	pushf
2f55     2f55:	58                   	pop    %rax
2f56     2f56:	fa                   	cli
2f57     2f57:	fb                   	sti
2f58     2f58:	9c                   	pushf
2f59     2f59:	58                   	pop    %rax
2f5a     2f5a:	fa                   	cli
2f5b     2f5b:	fb                   	sti
2f5c     2f5c:	9c                   	pushf
2f5d     2f5d:	58                   	pop    %rax
2f5e     2f5e:	fa                   	cli
2f5f     2f5f:	9c                   	pushf
2f60     2f60:	58                   	pop    %rax
2f61     2f61:	fb                   	sti
2f62     2f62:	9c                   	pushf
2f63     2f63:	58                   	pop    %rax
2f64     2f64:	fa                   	cli
2f65     2f65:	9c                   	pushf
2f66     2f66:	58                   	pop    %rax
2f67     2f67:	fb                   	sti
2f68     2f68:	e9 00 00 00 00       	jmp    2f6d <.altinstr_replacement+0x2f6d>	2f69: R_X86_64_PC32	.text+0xbf259e
2f6d     2f6d:	48 89 f8             	mov    %rdi,%rax
2f70     2f70:	e9 00 00 00 00       	jmp    2f75 <.altinstr_replacement+0x2f75>	2f71: R_X86_64_PC32	.text+0xbf262d
2f75     2f75:	e9 00 00 00 00       	jmp    2f7a <.altinstr_replacement+0x2f7a>	2f76: R_X86_64_PC32	.text+0xbf2683
2f7a     2f7a:	48 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbp
2f84     2f84:	48 89 f8             	mov    %rdi,%rax
2f87     2f87:	48 89 f8             	mov    %rdi,%rax
2f8a     2f8a:	48 89 f8             	mov    %rdi,%rax
2f8d     2f8d:	48 89 f8             	mov    %rdi,%rax
2f90     2f90:	48 89 f8             	mov    %rdi,%rax
2f93     2f93:	48 89 f8             	mov    %rdi,%rax
2f96     2f96:	48 89 f8             	mov    %rdi,%rax
2f99     2f99:	48 89 f8             	mov    %rdi,%rax
2f9c     2f9c:	e9 00 00 00 00       	jmp    2fa1 <.altinstr_replacement+0x2fa1>	2f9d: R_X86_64_PC32	.text+0xbf68ed
2fa1     2fa1:	48 89 f8             	mov    %rdi,%rax
2fa4     2fa4:	48 89 f8             	mov    %rdi,%rax
2fa7     2fa7:	48 89 f8             	mov    %rdi,%rax
2faa     2faa:	48 89 f8             	mov    %rdi,%rax
2fad     2fad:	48 89 f8             	mov    %rdi,%rax
2fb0     2fb0:	e9 00 00 00 00       	jmp    2fb5 <.altinstr_replacement+0x2fb5>	2fb1: R_X86_64_PC32	.text+0xbfb1e6
2fb5     2fb5:	e9 00 00 00 00       	jmp    2fba <.altinstr_replacement+0x2fba>	2fb6: R_X86_64_PC32	.text+0xbfb0d0
2fba     2fba:	e9 00 00 00 00       	jmp    2fbf <.altinstr_replacement+0x2fbf>	2fbb: R_X86_64_PC32	.text+0xbff2d8
2fbf     2fbf:	e9 00 00 00 00       	jmp    2fc4 <.altinstr_replacement+0x2fc4>	2fc0: R_X86_64_PC32	.text+0xbff551
2fc4     2fc4:	e9 00 00 00 00       	jmp    2fc9 <.altinstr_replacement+0x2fc9>	2fc5: R_X86_64_PC32	.text+0xbfffeb
2fc9     2fc9:	e9 00 00 00 00       	jmp    2fce <.altinstr_replacement+0x2fce>	2fca: R_X86_64_PC32	.text+0xc003d0
2fce     2fce:	e9 00 00 00 00       	jmp    2fd3 <.altinstr_replacement+0x2fd3>	2fcf: R_X86_64_PC32	.text+0xc00191
2fd3     2fd3:	e9 00 00 00 00       	jmp    2fd8 <.altinstr_replacement+0x2fd8>	2fd4: R_X86_64_PC32	.text+0xc00198
2fd8     2fd8:	e9 00 00 00 00       	jmp    2fdd <.altinstr_replacement+0x2fdd>	2fd9: R_X86_64_PC32	.text+0xc009c6
2fdd     2fdd:	e9 00 00 00 00       	jmp    2fe2 <.altinstr_replacement+0x2fe2>	2fde: R_X86_64_PC32	.text+0xc008b1
2fe2     2fe2:	e9 00 00 00 00       	jmp    2fe7 <.altinstr_replacement+0x2fe7>	2fe3: R_X86_64_PC32	.text.unlikely+0x835be
2fe7     2fe7:	48 89 f8             	mov    %rdi,%rax
2fea     2fea:	e9 00 00 00 00       	jmp    2fef <.altinstr_replacement+0x2fef>	2feb: R_X86_64_PC32	.text.unlikely+0x83a1a
2fef     2fef:	48 89 f8             	mov    %rdi,%rax
2ff2     2ff2:	48 89 f8             	mov    %rdi,%rax
2ff5     2ff5:	48 89 f8             	mov    %rdi,%rax
2ff8     2ff8:	48 89 f8             	mov    %rdi,%rax
2ffb     2ffb:	48 89 f8             	mov    %rdi,%rax
2ffe     2ffe:	48 89 f8             	mov    %rdi,%rax
3001     3001:	48 89 f8             	mov    %rdi,%rax
3004     3004:	48 89 f8             	mov    %rdi,%rax
3007     3007:	48 89 f8             	mov    %rdi,%rax
300a     300a:	e9 00 00 00 00       	jmp    300f <.altinstr_replacement+0x300f>	300b: R_X86_64_PC32	.text.unlikely+0x846b8
300f     300f:	e9 00 00 00 00       	jmp    3014 <.altinstr_replacement+0x3014>	3010: R_X86_64_PC32	.text.unlikely+0x8467e
3014     3014:	9c                   	pushf
3015     3015:	58                   	pop    %rax
3016     3016:	fa                   	cli
3017     3017:	9c                   	pushf
3018     3018:	58                   	pop    %rax
3019     3019:	fb                   	sti
301a     301a:	e9 00 00 00 00       	jmp    301f <.altinstr_replacement+0x301f>	301b: R_X86_64_PC32	.init.text+0xf20e4
301f     301f:	e9 00 00 00 00       	jmp    3024 <.altinstr_replacement+0x3024>	3020: R_X86_64_PC32	.text.unlikely+0x84f44
3024     3024:	e9 00 00 00 00       	jmp    3029 <.altinstr_replacement+0x3029>	3025: R_X86_64_PC32	.init.text+0xf299c
3029     3029:	e9 00 00 00 00       	jmp    302e <.altinstr_replacement+0x302e>	302a: R_X86_64_PC32	.init.text+0xf29e1
302e     302e:	e9 00 00 00 00       	jmp    3033 <.altinstr_replacement+0x3033>	302f: R_X86_64_PC32	.init.text+0xf2a63
3033     3033:	e9 00 00 00 00       	jmp    3038 <.altinstr_replacement+0x3038>	3034: R_X86_64_PC32	.init.text+0xf2c15
3038     3038:	e9 00 00 00 00       	jmp    303d <.altinstr_replacement+0x303d>	3039: R_X86_64_PC32	.init.text+0xf2c56
303d     303d:	e9 00 00 00 00       	jmp    3042 <.altinstr_replacement+0x3042>	303e: R_X86_64_PC32	.text.unlikely+0x84fa5
3042     3042:	e9 00 00 00 00       	jmp    3047 <.altinstr_replacement+0x3047>	3043: R_X86_64_PC32	.text.unlikely+0x84ff1
3047     3047:	49 bf 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r15
3051     3051:	e9 00 00 00 00       	jmp    3056 <.altinstr_replacement+0x3056>	3052: R_X86_64_PC32	.text+0xc0549c
3056     3056:	e9 00 00 00 00       	jmp    305b <.altinstr_replacement+0x305b>	3057: R_X86_64_PC32	.text+0xc054e2
305b     305b:	e9 00 00 00 00       	jmp    3060 <.altinstr_replacement+0x3060>	305c: R_X86_64_PC32	.text+0xc05d2c
3060     3060:	e9 00 00 00 00       	jmp    3065 <.altinstr_replacement+0x3065>	3061: R_X86_64_PC32	.text+0xc05d40
3065     3065:	e9 00 00 00 00       	jmp    306a <.altinstr_replacement+0x306a>	3066: R_X86_64_PC32	.text+0xc05d36
306a     306a:	e9 00 00 00 00       	jmp    306f <.altinstr_replacement+0x306f>	306b: R_X86_64_PC32	.text+0xc05d56
306f     306f:	e9 00 00 00 00       	jmp    3074 <.altinstr_replacement+0x3074>	3070: R_X86_64_PC32	.text.unlikely+0x86083
3074     3074:	e9 00 00 00 00       	jmp    3079 <.altinstr_replacement+0x3079>	3075: R_X86_64_PC32	.text.unlikely+0x860c7
3079     3079:	e9 00 00 00 00       	jmp    307e <.altinstr_replacement+0x307e>	307a: R_X86_64_PC32	.text+0xc20fca
307e     307e:	e9 00 00 00 00       	jmp    3083 <.altinstr_replacement+0x3083>	307f: R_X86_64_PC32	.text.unlikely+0x86659
3083     3083:	e9 00 00 00 00       	jmp    3088 <.altinstr_replacement+0x3088>	3084: R_X86_64_PC32	.text+0xc211b7
3088     3088:	e9 00 00 00 00       	jmp    308d <.altinstr_replacement+0x308d>	3089: R_X86_64_PC32	.text+0xc21671
308d     308d:	e9 00 00 00 00       	jmp    3092 <.altinstr_replacement+0x3092>	308e: R_X86_64_PC32	.text+0xc21454
3092     3092:	e9 00 00 00 00       	jmp    3097 <.altinstr_replacement+0x3097>	3093: R_X86_64_PC32	.text+0xc21ae9
3097     3097:	e9 00 00 00 00       	jmp    309c <.altinstr_replacement+0x309c>	3098: R_X86_64_PC32	.text+0xc218d0
309c     309c:	48 89 f8             	mov    %rdi,%rax
309f     309f:	48 89 f8             	mov    %rdi,%rax
30a2     30a2:	48 89 f8             	mov    %rdi,%rax
30a5     30a5:	48 89 f8             	mov    %rdi,%rax
30a8     30a8:	48 89 f8             	mov    %rdi,%rax
30ab     30ab:	48 89 f8             	mov    %rdi,%rax
30ae     30ae:	48 89 f8             	mov    %rdi,%rax
30b1     30b1:	48 89 f8             	mov    %rdi,%rax
30b4     30b4:	48 89 f8             	mov    %rdi,%rax
30b7     30b7:	48 89 f8             	mov    %rdi,%rax
30ba     30ba:	48 89 f8             	mov    %rdi,%rax
30bd     30bd:	48 89 f8             	mov    %rdi,%rax
30c0     30c0:	48 89 f8             	mov    %rdi,%rax
30c3     30c3:	48 89 f8             	mov    %rdi,%rax
30c6     30c6:	48 89 f8             	mov    %rdi,%rax
30c9     30c9:	48 89 f8             	mov    %rdi,%rax
30cc     30cc:	48 89 f8             	mov    %rdi,%rax
30cf     30cf:	48 89 f8             	mov    %rdi,%rax
30d2     30d2:	48 89 f8             	mov    %rdi,%rax
30d5     30d5:	48 89 f8             	mov    %rdi,%rax
30d8     30d8:	48 89 f8             	mov    %rdi,%rax
30db     30db:	e9 00 00 00 00       	jmp    30e0 <.altinstr_replacement+0x30e0>	30dc: R_X86_64_PC32	.text+0xc23c92
30e0     30e0:	e9 00 00 00 00       	jmp    30e5 <.altinstr_replacement+0x30e5>	30e1: R_X86_64_PC32	.text+0xc23d2b
30e5     30e5:	48 89 f8             	mov    %rdi,%rax
30e8     30e8:	48 89 f8             	mov    %rdi,%rax
30eb     30eb:	48 89 f8             	mov    %rdi,%rax
30ee     30ee:	48 89 f8             	mov    %rdi,%rax
30f1     30f1:	48 89 f8             	mov    %rdi,%rax
30f4     30f4:	48 89 f8             	mov    %rdi,%rax
30f7     30f7:	48 89 f8             	mov    %rdi,%rax
30fa     30fa:	48 89 f8             	mov    %rdi,%rax
30fd     30fd:	48 89 f8             	mov    %rdi,%rax
3100     3100:	48 89 f8             	mov    %rdi,%rax
3103     3103:	48 89 f8             	mov    %rdi,%rax
3106     3106:	48 89 f8             	mov    %rdi,%rax
3109     3109:	48 89 f8             	mov    %rdi,%rax
310c     310c:	48 89 f8             	mov    %rdi,%rax
310f     310f:	48 89 f8             	mov    %rdi,%rax
3112     3112:	48 89 f8             	mov    %rdi,%rax
3115     3115:	48 89 f8             	mov    %rdi,%rax
3118     3118:	48 89 f8             	mov    %rdi,%rax
311b     311b:	48 89 f8             	mov    %rdi,%rax
311e     311e:	48 89 f8             	mov    %rdi,%rax
3121     3121:	48 89 f8             	mov    %rdi,%rax
3124     3124:	48 89 f8             	mov    %rdi,%rax
3127     3127:	48 89 f8             	mov    %rdi,%rax
312a     312a:	48 89 f8             	mov    %rdi,%rax
312d     312d:	48 89 f8             	mov    %rdi,%rax
3130     3130:	48 89 f8             	mov    %rdi,%rax
3133     3133:	48 89 f8             	mov    %rdi,%rax
3136     3136:	48 89 f8             	mov    %rdi,%rax
3139     3139:	48 89 f8             	mov    %rdi,%rax
313c     313c:	48 89 f8             	mov    %rdi,%rax
313f     313f:	48 89 f8             	mov    %rdi,%rax
3142     3142:	48 89 f8             	mov    %rdi,%rax
3145     3145:	48 89 f8             	mov    %rdi,%rax
3148     3148:	e9 00 00 00 00       	jmp    314d <.altinstr_replacement+0x314d>	3149: R_X86_64_PC32	.text+0xc50bed
314d     314d:	e9 00 00 00 00       	jmp    3152 <.altinstr_replacement+0x3152>	314e: R_X86_64_PC32	.text+0xc50c43
3152     3152:	48 89 f8             	mov    %rdi,%rax
3155     3155:	48 89 f8             	mov    %rdi,%rax
3158     3158:	48 89 f8             	mov    %rdi,%rax
315b     315b:	48 89 f8             	mov    %rdi,%rax
315e     315e:	48 89 f8             	mov    %rdi,%rax
3161     3161:	48 89 f8             	mov    %rdi,%rax
3164     3164:	48 89 f8             	mov    %rdi,%rax
3167     3167:	48 89 f8             	mov    %rdi,%rax
316a     316a:	48 89 f8             	mov    %rdi,%rax
316d     316d:	48 89 f8             	mov    %rdi,%rax
3170     3170:	48 89 f8             	mov    %rdi,%rax
3173     3173:	48 89 f8             	mov    %rdi,%rax
3176     3176:	48 89 f8             	mov    %rdi,%rax
3179     3179:	48 89 f8             	mov    %rdi,%rax
317c     317c:	48 89 f8             	mov    %rdi,%rax
317f     317f:	48 89 f8             	mov    %rdi,%rax
3182     3182:	48 89 f8             	mov    %rdi,%rax
3185     3185:	48 89 f8             	mov    %rdi,%rax
3188     3188:	48 89 f8             	mov    %rdi,%rax
318b     318b:	48 89 f8             	mov    %rdi,%rax
318e     318e:	48 89 f8             	mov    %rdi,%rax
3191     3191:	48 89 f8             	mov    %rdi,%rax
3194     3194:	48 89 f8             	mov    %rdi,%rax
3197     3197:	48 89 f8             	mov    %rdi,%rax
319a     319a:	48 89 f8             	mov    %rdi,%rax
319d     319d:	48 89 f8             	mov    %rdi,%rax
31a0     31a0:	48 89 f8             	mov    %rdi,%rax
31a3     31a3:	48 89 f8             	mov    %rdi,%rax
31a6     31a6:	48 89 f8             	mov    %rdi,%rax
31a9     31a9:	48 89 f8             	mov    %rdi,%rax
31ac     31ac:	48 89 f8             	mov    %rdi,%rax
31af     31af:	48 89 f8             	mov    %rdi,%rax
31b2     31b2:	48 89 f8             	mov    %rdi,%rax
31b5     31b5:	48 89 f8             	mov    %rdi,%rax
31b8     31b8:	48 89 f8             	mov    %rdi,%rax
31bb     31bb:	48 89 f8             	mov    %rdi,%rax
31be     31be:	48 89 f8             	mov    %rdi,%rax
31c1     31c1:	48 89 f8             	mov    %rdi,%rax
31c4     31c4:	48 89 f8             	mov    %rdi,%rax
31c7     31c7:	48 89 f8             	mov    %rdi,%rax
31ca     31ca:	e9 00 00 00 00       	jmp    31cf <.altinstr_replacement+0x31cf>	31cb: R_X86_64_PC32	.text.unlikely+0x8731b
31cf     31cf:	e9 00 00 00 00       	jmp    31d4 <.altinstr_replacement+0x31d4>	31d0: R_X86_64_PC32	.init.text+0xfa976
31d4     31d4:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
31de     31de:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
31e8     31e8:	48 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbp
31f2     31f2:	9c                   	pushf
31f3     31f3:	58                   	pop    %rax
31f4     31f4:	fa                   	cli
31f5     31f5:	fb                   	sti
31f6     31f6:	49 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r13
3200     3200:	9c                   	pushf
3201     3201:	58                   	pop    %rax
3202     3202:	fa                   	cli
3203     3203:	9c                   	pushf
3204     3204:	58                   	pop    %rax
3205     3205:	fb                   	sti
3206     3206:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
3210     3210:	0f 01 cb             	stac
3213     3213:	0f ae e8             	lfence
3216     3216:	0f 01 ca             	clac
3219     3219:	0f 01 ca             	clac
321c     321c:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
3226     3226:	0f 01 cb             	stac
3229     3229:	0f ae e8             	lfence
322c     322c:	0f 01 ca             	clac
322f     322f:	0f 01 ca             	clac
3232     3232:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
323c     323c:	0f 01 cb             	stac
323f     323f:	0f ae e8             	lfence
3242     3242:	0f 01 ca             	clac
3245     3245:	0f 01 ca             	clac
3248     3248:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
3252     3252:	0f 01 cb             	stac
3255     3255:	0f ae e8             	lfence
3258     3258:	0f 01 ca             	clac
325b     325b:	0f 01 ca             	clac
325e     325e:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
3268     3268:	0f 01 cb             	stac
326b     326b:	0f ae e8             	lfence
326e     326e:	0f 01 ca             	clac
3271     3271:	0f 01 ca             	clac
3274     3274:	0f 01 ca             	clac
3277     3277:	49 bf 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r15
3281     3281:	0f 01 cb             	stac
3284     3284:	0f ae e8             	lfence
3287     3287:	0f 01 ca             	clac
328a     328a:	48 ba 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rdx
3294     3294:	0f 01 cb             	stac
3297     3297:	0f ae e8             	lfence
329a     329a:	0f 01 ca             	clac
329d     329d:	0f 01 ca             	clac
32a0     32a0:	48 ba 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rdx
32aa     32aa:	0f 01 cb             	stac
32ad     32ad:	0f ae e8             	lfence
32b0     32b0:	0f 01 ca             	clac
32b3     32b3:	0f 01 ca             	clac
32b6     32b6:	48 ba 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rdx
32c0     32c0:	0f 01 cb             	stac
32c3     32c3:	0f ae e8             	lfence
32c6     32c6:	0f 01 ca             	clac
32c9     32c9:	0f 01 ca             	clac
32cc     32cc:	48 ba 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rdx
32d6     32d6:	0f 01 cb             	stac
32d9     32d9:	0f ae e8             	lfence
32dc     32dc:	0f 01 ca             	clac
32df     32df:	0f 01 ca             	clac
32e2     32e2:	e8 00 00 00 00       	call   32e7 <.altinstr_replacement+0x32e7>	32e3: R_X86_64_PLT32	copy_user_generic_string-0x4
32e7     32e7:	e8 00 00 00 00       	call   32ec <.altinstr_replacement+0x32ec>	32e8: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
32ec     32ec:	e8 00 00 00 00       	call   32f1 <.altinstr_replacement+0x32f1>	32ed: R_X86_64_PLT32	copy_user_generic_string-0x4
32f1     32f1:	e8 00 00 00 00       	call   32f6 <.altinstr_replacement+0x32f6>	32f2: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
32f6     32f6:	e8 00 00 00 00       	call   32fb <.altinstr_replacement+0x32fb>	32f7: R_X86_64_PLT32	copy_user_generic_string-0x4
32fb     32fb:	e8 00 00 00 00       	call   3300 <.altinstr_replacement+0x3300>	32fc: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
3300     3300:	48 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbp
330a     330a:	0f 01 cb             	stac
330d     330d:	0f ae e8             	lfence
3310     3310:	0f 01 ca             	clac
3313     3313:	0f 01 ca             	clac
3316     3316:	48 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbp
3320     3320:	0f 01 cb             	stac
3323     3323:	0f ae e8             	lfence
3326     3326:	0f 01 ca             	clac
3329     3329:	0f 01 ca             	clac
332c     332c:	9c                   	pushf
332d     332d:	58                   	pop    %rax
332e     332e:	fa                   	cli
332f     332f:	9c                   	pushf
3330     3330:	58                   	pop    %rax
3331     3331:	fb                   	sti
3332     3332:	41 0f 0d 8c 24 80 05 00 00 	prefetchw 0x580(%r12)
333b     333b:	9c                   	pushf
333c     333c:	58                   	pop    %rax
333d     333d:	fa                   	cli
333e     333e:	9c                   	pushf
333f     333f:	58                   	pop    %rax
3340     3340:	fb                   	sti
3341     3341:	f3 0f b8 c7          	popcnt %edi,%eax
3345     3345:	f3 0f b8 c7          	popcnt %edi,%eax
3349     3349:	9c                   	pushf
334a     334a:	58                   	pop    %rax
334b     334b:	fa                   	cli
334c     334c:	9c                   	pushf
334d     334d:	58                   	pop    %rax
334e     334e:	fb                   	sti
334f     334f:	9c                   	pushf
3350     3350:	58                   	pop    %rax
3351     3351:	9c                   	pushf
3352     3352:	58                   	pop    %rax
3353     3353:	fa                   	cli
3354     3354:	fb                   	sti
3355     3355:	9c                   	pushf
3356     3356:	58                   	pop    %rax
3357     3357:	9c                   	pushf
3358     3358:	58                   	pop    %rax
3359     3359:	fa                   	cli
335a     335a:	fb                   	sti
335b     335b:	fb                   	sti
335c     335c:	9c                   	pushf
335d     335d:	58                   	pop    %rax
335e     335e:	fa                   	cli
335f     335f:	fb                   	sti
3360     3360:	41 0f 0d 0c 24       	prefetchw (%r12)
3365     3365:	49 bf 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r15
336f     336f:	e9 00 00 00 00       	jmp    3374 <.altinstr_replacement+0x3374>	3370: R_X86_64_PC32	.text+0xd6571e
3374     3374:	48 89 f8             	mov    %rdi,%rax
3377     3377:	9c                   	pushf
3378     3378:	58                   	pop    %rax
3379     3379:	fa                   	cli
337a     337a:	9c                   	pushf
337b     337b:	58                   	pop    %rax
337c     337c:	fb                   	sti
337d     337d:	48 89 f8             	mov    %rdi,%rax
3380     3380:	48 89 f8             	mov    %rdi,%rax
3383     3383:	e9 00 00 00 00       	jmp    3388 <.altinstr_replacement+0x3388>	3384: R_X86_64_PC32	.text+0xd6aca9
3388     3388:	48 89 f8             	mov    %rdi,%rax
338b     338b:	48 89 f8             	mov    %rdi,%rax
338e     338e:	48 89 f8             	mov    %rdi,%rax
3391     3391:	48 89 f8             	mov    %rdi,%rax
3394     3394:	9c                   	pushf
3395     3395:	58                   	pop    %rax
3396     3396:	fa                   	cli
3397     3397:	9c                   	pushf
3398     3398:	58                   	pop    %rax
3399     3399:	fb                   	sti
339a     339a:	9c                   	pushf
339b     339b:	58                   	pop    %rax
339c     339c:	fa                   	cli
339d     339d:	9c                   	pushf
339e     339e:	58                   	pop    %rax
339f     339f:	fb                   	sti
33a0     33a0:	9c                   	pushf
33a1     33a1:	58                   	pop    %rax
33a2     33a2:	fa                   	cli
33a3     33a3:	9c                   	pushf
33a4     33a4:	58                   	pop    %rax
33a5     33a5:	fb                   	sti
33a6     33a6:	9c                   	pushf
33a7     33a7:	58                   	pop    %rax
33a8     33a8:	fa                   	cli
33a9     33a9:	9c                   	pushf
33aa     33aa:	58                   	pop    %rax
33ab     33ab:	fb                   	sti
33ac     33ac:	e8 00 00 00 00       	call   33b1 <.altinstr_replacement+0x33b1>	33ad: R_X86_64_PLT32	clear_page_rep-0x4
33b1     33b1:	e8 00 00 00 00       	call   33b6 <.altinstr_replacement+0x33b6>	33b2: R_X86_64_PLT32	clear_page_erms-0x4
33b6     33b6:	48 89 f8             	mov    %rdi,%rax
33b9     33b9:	48 89 f8             	mov    %rdi,%rax
33bc     33bc:	48 89 f8             	mov    %rdi,%rax
33bf     33bf:	48 89 f8             	mov    %rdi,%rax
33c2     33c2:	48 89 f8             	mov    %rdi,%rax
33c5     33c5:	48 89 f8             	mov    %rdi,%rax
33c8     33c8:	48 89 f8             	mov    %rdi,%rax
33cb     33cb:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
33d5     33d5:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
33df     33df:	48 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbp
33e9     33e9:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
33f3     33f3:	48 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbp
33fd     33fd:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
3407     3407:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
3411     3411:	49 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r13
341b     341b:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
3425     3425:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
342f     342f:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
3439     3439:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
3443     3443:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
344d     344d:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
3457     3457:	48 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbp
3461     3461:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
346b     346b:	49 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r13
3475     3475:	48 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbp
347f     347f:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
3489     3489:	48 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbp
3493     3493:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
349d     349d:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
34a7     34a7:	e9 00 00 00 00       	jmp    34ac <.altinstr_replacement+0x34ac>	34a8: R_X86_64_PC32	.text+0xdf703c
34ac     34ac:	48 89 f8             	mov    %rdi,%rax
34af     34af:	e9 00 00 00 00       	jmp    34b4 <.altinstr_replacement+0x34b4>	34b0: R_X86_64_PC32	.text+0xdfa06d
34b4     34b4:	e9 00 00 00 00       	jmp    34b9 <.altinstr_replacement+0x34b9>	34b5: R_X86_64_PC32	.text+0xdfa0c3
34b9     34b9:	48 89 f8             	mov    %rdi,%rax
34bc     34bc:	48 89 f8             	mov    %rdi,%rax
34bf     34bf:	48 89 f8             	mov    %rdi,%rax
34c2     34c2:	48 89 f8             	mov    %rdi,%rax
34c5     34c5:	48 89 f8             	mov    %rdi,%rax
34c8     34c8:	48 89 f8             	mov    %rdi,%rax
34cb     34cb:	48 89 f8             	mov    %rdi,%rax
34ce     34ce:	48 89 f8             	mov    %rdi,%rax
34d1     34d1:	48 89 f8             	mov    %rdi,%rax
34d4     34d4:	48 89 f8             	mov    %rdi,%rax
34d7     34d7:	48 89 f8             	mov    %rdi,%rax
34da     34da:	e9 00 00 00 00       	jmp    34df <.altinstr_replacement+0x34df>	34db: R_X86_64_PC32	.text+0xdfd3b3
34df     34df:	e9 00 00 00 00       	jmp    34e4 <.altinstr_replacement+0x34e4>	34e0: R_X86_64_PC32	.text+0xdfd40c
34e4     34e4:	48 89 f8             	mov    %rdi,%rax
34e7     34e7:	e9 00 00 00 00       	jmp    34ec <.altinstr_replacement+0x34ec>	34e8: R_X86_64_PC32	.text+0xdfd95a
34ec     34ec:	48 89 f8             	mov    %rdi,%rax
34ef     34ef:	e9 00 00 00 00       	jmp    34f4 <.altinstr_replacement+0x34f4>	34f0: R_X86_64_PC32	.text+0xdfe056
34f4     34f4:	48 89 f8             	mov    %rdi,%rax
34f7     34f7:	e9 00 00 00 00       	jmp    34fc <.altinstr_replacement+0x34fc>	34f8: R_X86_64_PC32	.text+0xdfe2af
34fc     34fc:	48 89 f8             	mov    %rdi,%rax
34ff     34ff:	48 89 f8             	mov    %rdi,%rax
3502     3502:	48 89 f8             	mov    %rdi,%rax
3505     3505:	48 89 f8             	mov    %rdi,%rax
3508     3508:	48 89 f8             	mov    %rdi,%rax
350b     350b:	48 89 f8             	mov    %rdi,%rax
350e     350e:	e9 00 00 00 00       	jmp    3513 <.altinstr_replacement+0x3513>	350f: R_X86_64_PC32	.text+0xdff180
3513     3513:	48 89 f8             	mov    %rdi,%rax
3516     3516:	48 89 f8             	mov    %rdi,%rax
3519     3519:	48 89 f8             	mov    %rdi,%rax
351c     351c:	48 89 f8             	mov    %rdi,%rax
351f     351f:	48 89 f8             	mov    %rdi,%rax
3522     3522:	48 89 f8             	mov    %rdi,%rax
3525     3525:	48 89 f8             	mov    %rdi,%rax
3528     3528:	e9 00 00 00 00       	jmp    352d <.altinstr_replacement+0x352d>	3529: R_X86_64_PC32	.text+0xe01a71
352d     352d:	48 89 f8             	mov    %rdi,%rax
3530     3530:	48 89 f8             	mov    %rdi,%rax
3533     3533:	48 89 f8             	mov    %rdi,%rax
3536     3536:	48 89 f8             	mov    %rdi,%rax
3539     3539:	48 89 f8             	mov    %rdi,%rax
353c     353c:	e9 00 00 00 00       	jmp    3541 <.altinstr_replacement+0x3541>	353d: R_X86_64_PC32	.text+0xe21aad
3541     3541:	e9 00 00 00 00       	jmp    3546 <.altinstr_replacement+0x3546>	3542: R_X86_64_PC32	.text+0xe2c46e
3546     3546:	e9 00 00 00 00       	jmp    354b <.altinstr_replacement+0x354b>	3547: R_X86_64_PC32	.text+0xe2d116
354b     354b:	e9 00 00 00 00       	jmp    3550 <.altinstr_replacement+0x3550>	354c: R_X86_64_PC32	.text+0xe2d15c
3550     3550:	e9 00 00 00 00       	jmp    3555 <.altinstr_replacement+0x3555>	3551: R_X86_64_PC32	.text+0xe2da91
3555     3555:	e9 00 00 00 00       	jmp    355a <.altinstr_replacement+0x355a>	3556: R_X86_64_PC32	.text+0xe2e2ea
355a     355a:	e9 00 00 00 00       	jmp    355f <.altinstr_replacement+0x355f>	355b: R_X86_64_PC32	.init.text+0x100bfd
355f     355f:	e9 00 00 00 00       	jmp    3564 <.altinstr_replacement+0x3564>	3560: R_X86_64_PC32	.init.text+0x100cb3
3564     3564:	f3 48 0f b8 c7       	popcnt %rdi,%rax
3569     3569:	0f 0d 4d 00          	prefetchw 0x0(%rbp)
356d     356d:	48 89 f8             	mov    %rdi,%rax
3570     3570:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
357a     357a:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
3584     3584:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
358e     358e:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
3598     3598:	f3 0f b8 c7          	popcnt %edi,%eax
359c     359c:	9c                   	pushf
359d     359d:	58                   	pop    %rax
359e     359e:	fa                   	cli
359f     359f:	9c                   	pushf
35a0     35a0:	58                   	pop    %rax
35a1     35a1:	fb                   	sti
35a2     35a2:	9c                   	pushf
35a3     35a3:	58                   	pop    %rax
35a4     35a4:	fa                   	cli
35a5     35a5:	9c                   	pushf
35a6     35a6:	58                   	pop    %rax
35a7     35a7:	fb                   	sti
35a8     35a8:	9c                   	pushf
35a9     35a9:	58                   	pop    %rax
35aa     35aa:	fa                   	cli
35ab     35ab:	9c                   	pushf
35ac     35ac:	58                   	pop    %rax
35ad     35ad:	fb                   	sti
35ae     35ae:	9c                   	pushf
35af     35af:	58                   	pop    %rax
35b0     35b0:	fa                   	cli
35b1     35b1:	9c                   	pushf
35b2     35b2:	58                   	pop    %rax
35b3     35b3:	fb                   	sti
35b4     35b4:	f3 0f b8 c7          	popcnt %edi,%eax
35b8     35b8:	f3 0f b8 c7          	popcnt %edi,%eax
35bc     35bc:	f3 0f b8 c7          	popcnt %edi,%eax
35c0     35c0:	f3 48 0f b8 c7       	popcnt %rdi,%rax
35c5     35c5:	f3 48 0f b8 c7       	popcnt %rdi,%rax
35ca     35ca:	e8 00 00 00 00       	call   35cf <.altinstr_replacement+0x35cf>	35cb: R_X86_64_PLT32	clear_page_rep-0x4
35cf     35cf:	e8 00 00 00 00       	call   35d4 <.altinstr_replacement+0x35d4>	35d0: R_X86_64_PLT32	clear_page_erms-0x4
35d4     35d4:	e8 00 00 00 00       	call   35d9 <.altinstr_replacement+0x35d9>	35d5: R_X86_64_PLT32	clear_page_rep-0x4
35d9     35d9:	e8 00 00 00 00       	call   35de <.altinstr_replacement+0x35de>	35da: R_X86_64_PLT32	clear_page_erms-0x4
35de     35de:	9c                   	pushf
35df     35df:	58                   	pop    %rax
35e0     35e0:	fa                   	cli
35e1     35e1:	9c                   	pushf
35e2     35e2:	58                   	pop    %rax
35e3     35e3:	fb                   	sti
35e4     35e4:	e8 00 00 00 00       	call   35e9 <.altinstr_replacement+0x35e9>	35e5: R_X86_64_PLT32	clear_page_rep-0x4
35e9     35e9:	e8 00 00 00 00       	call   35ee <.altinstr_replacement+0x35ee>	35ea: R_X86_64_PLT32	clear_page_erms-0x4
35ee     35ee:	e8 00 00 00 00       	call   35f3 <.altinstr_replacement+0x35f3>	35ef: R_X86_64_PLT32	clear_page_rep-0x4
35f3     35f3:	e8 00 00 00 00       	call   35f8 <.altinstr_replacement+0x35f8>	35f4: R_X86_64_PLT32	clear_page_erms-0x4
35f8     35f8:	f3 0f b8 c7          	popcnt %edi,%eax
35fc     35fc:	f3 48 0f b8 c7       	popcnt %rdi,%rax
3601     3601:	f3 0f b8 c7          	popcnt %edi,%eax
3605     3605:	f3 0f b8 c7          	popcnt %edi,%eax
3609     3609:	f3 0f b8 c7          	popcnt %edi,%eax
360d     360d:	f3 48 0f b8 c7       	popcnt %rdi,%rax
3612     3612:	9c                   	pushf
3613     3613:	58                   	pop    %rax
3614     3614:	fa                   	cli
3615     3615:	9c                   	pushf
3616     3616:	58                   	pop    %rax
3617     3617:	fb                   	sti
3618     3618:	9c                   	pushf
3619     3619:	58                   	pop    %rax
361a     361a:	fa                   	cli
361b     361b:	9c                   	pushf
361c     361c:	58                   	pop    %rax
361d     361d:	fb                   	sti
361e     361e:	9c                   	pushf
361f     361f:	58                   	pop    %rax
3620     3620:	fa                   	cli
3621     3621:	9c                   	pushf
3622     3622:	58                   	pop    %rax
3623     3623:	fb                   	sti
3624     3624:	f3 0f b8 c7          	popcnt %edi,%eax
3628     3628:	f3 0f b8 c7          	popcnt %edi,%eax
362c     362c:	f3 0f b8 c7          	popcnt %edi,%eax
3630     3630:	f3 48 0f b8 c7       	popcnt %rdi,%rax
3635     3635:	f3 48 0f b8 c7       	popcnt %rdi,%rax
363a     363a:	f3 48 0f b8 c7       	popcnt %rdi,%rax
363f     363f:	f3 48 0f b8 c7       	popcnt %rdi,%rax
3644     3644:	f3 48 0f b8 c7       	popcnt %rdi,%rax
3649     3649:	f3 0f b8 c7          	popcnt %edi,%eax
364d     364d:	f3 48 0f b8 c7       	popcnt %rdi,%rax
3652     3652:	e8 00 00 00 00       	call   3657 <.altinstr_replacement+0x3657>	3653: R_X86_64_PLT32	clear_page_rep-0x4
3657     3657:	e8 00 00 00 00       	call   365c <.altinstr_replacement+0x365c>	3658: R_X86_64_PLT32	clear_page_erms-0x4
365c     365c:	9c                   	pushf
365d     365d:	58                   	pop    %rax
365e     365e:	fa                   	cli
365f     365f:	9c                   	pushf
3660     3660:	58                   	pop    %rax
3661     3661:	fb                   	sti
3662     3662:	e8 00 00 00 00       	call   3667 <.altinstr_replacement+0x3667>	3663: R_X86_64_PLT32	clear_page_rep-0x4
3667     3667:	e8 00 00 00 00       	call   366c <.altinstr_replacement+0x366c>	3668: R_X86_64_PLT32	clear_page_erms-0x4
366c     366c:	e8 00 00 00 00       	call   3671 <.altinstr_replacement+0x3671>	366d: R_X86_64_PLT32	clear_page_rep-0x4
3671     3671:	e8 00 00 00 00       	call   3676 <.altinstr_replacement+0x3676>	3672: R_X86_64_PLT32	clear_page_erms-0x4
3676     3676:	f3 48 0f b8 c7       	popcnt %rdi,%rax
367b     367b:	f3 48 0f b8 c7       	popcnt %rdi,%rax
3680     3680:	9c                   	pushf
3681     3681:	58                   	pop    %rax
3682     3682:	fa                   	cli
3683     3683:	9c                   	pushf
3684     3684:	58                   	pop    %rax
3685     3685:	fb                   	sti
3686     3686:	e8 00 00 00 00       	call   368b <.altinstr_replacement+0x368b>	3687: R_X86_64_PLT32	clear_page_rep-0x4
368b     368b:	e8 00 00 00 00       	call   3690 <.altinstr_replacement+0x3690>	368c: R_X86_64_PLT32	clear_page_erms-0x4
3690     3690:	e8 00 00 00 00       	call   3695 <.altinstr_replacement+0x3695>	3691: R_X86_64_PLT32	clear_page_rep-0x4
3695     3695:	e8 00 00 00 00       	call   369a <.altinstr_replacement+0x369a>	3696: R_X86_64_PLT32	clear_page_erms-0x4
369a     369a:	e8 00 00 00 00       	call   369f <.altinstr_replacement+0x369f>	369b: R_X86_64_PLT32	clear_page_rep-0x4
369f     369f:	e8 00 00 00 00       	call   36a4 <.altinstr_replacement+0x36a4>	36a0: R_X86_64_PLT32	clear_page_erms-0x4
36a4     36a4:	0f 0d 4d 00          	prefetchw 0x0(%rbp)
36a8     36a8:	9c                   	pushf
36a9     36a9:	58                   	pop    %rax
36aa     36aa:	fa                   	cli
36ab     36ab:	9c                   	pushf
36ac     36ac:	58                   	pop    %rax
36ad     36ad:	fb                   	sti
36ae     36ae:	9c                   	pushf
36af     36af:	58                   	pop    %rax
36b0     36b0:	fa                   	cli
36b1     36b1:	9c                   	pushf
36b2     36b2:	58                   	pop    %rax
36b3     36b3:	fb                   	sti
36b4     36b4:	9c                   	pushf
36b5     36b5:	58                   	pop    %rax
36b6     36b6:	fa                   	cli
36b7     36b7:	9c                   	pushf
36b8     36b8:	58                   	pop    %rax
36b9     36b9:	fb                   	sti
36ba     36ba:	49 be 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r14
36c4     36c4:	e9 00 00 00 00       	jmp    36c9 <.altinstr_replacement+0x36c9>	36c5: R_X86_64_PC32	.text+0x21ac8f8
36c9     36c9:	e9 00 00 00 00       	jmp    36ce <.altinstr_replacement+0x36ce>	36ca: R_X86_64_PC32	.text+0x21aca2d
36ce     36ce:	e9 00 00 00 00       	jmp    36d3 <.altinstr_replacement+0x36d3>	36cf: R_X86_64_PC32	.text+0x21acc96
36d3     36d3:	e9 00 00 00 00       	jmp    36d8 <.altinstr_replacement+0x36d8>	36d4: R_X86_64_PC32	.text+0x21acd91
36d8     36d8:	9c                   	pushf
36d9     36d9:	58                   	pop    %rax
36da     36da:	9c                   	pushf
36db     36db:	58                   	pop    %rax
36dc     36dc:	9c                   	pushf
36dd     36dd:	58                   	pop    %rax
36de     36de:	fa                   	cli
36df     36df:	9c                   	pushf
36e0     36e0:	58                   	pop    %rax
36e1     36e1:	fb                   	sti
36e2     36e2:	f3 0f b8 c7          	popcnt %edi,%eax
36e6     36e6:	9c                   	pushf
36e7     36e7:	58                   	pop    %rax
36e8     36e8:	fa                   	cli
36e9     36e9:	9c                   	pushf
36ea     36ea:	58                   	pop    %rax
36eb     36eb:	fb                   	sti
36ec     36ec:	9c                   	pushf
36ed     36ed:	58                   	pop    %rax
36ee     36ee:	fa                   	cli
36ef     36ef:	9c                   	pushf
36f0     36f0:	58                   	pop    %rax
36f1     36f1:	fb                   	sti
36f2     36f2:	9c                   	pushf
36f3     36f3:	58                   	pop    %rax
36f4     36f4:	9c                   	pushf
36f5     36f5:	58                   	pop    %rax
36f6     36f6:	9c                   	pushf
36f7     36f7:	58                   	pop    %rax
36f8     36f8:	fa                   	cli
36f9     36f9:	9c                   	pushf
36fa     36fa:	58                   	pop    %rax
36fb     36fb:	fb                   	sti
36fc     36fc:	9c                   	pushf
36fd     36fd:	58                   	pop    %rax
36fe     36fe:	fa                   	cli
36ff     36ff:	9c                   	pushf
3700     3700:	58                   	pop    %rax
3701     3701:	fb                   	sti
3702     3702:	f3 0f b8 c7          	popcnt %edi,%eax
3706     3706:	f3 0f b8 c7          	popcnt %edi,%eax
370a     370a:	f3 0f b8 c7          	popcnt %edi,%eax
370e     370e:	f3 0f b8 c7          	popcnt %edi,%eax
3712     3712:	f3 0f b8 c7          	popcnt %edi,%eax
3716     3716:	f3 0f b8 c7          	popcnt %edi,%eax
371a     371a:	f3 0f b8 c7          	popcnt %edi,%eax
371e     371e:	49 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r13
3728     3728:	f3 0f b8 c7          	popcnt %edi,%eax
372c     372c:	f3 0f b8 c7          	popcnt %edi,%eax
3730     3730:	49 bf 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r15
373a     373a:	49 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r13
3744     3744:	f3 48 0f b8 c7       	popcnt %rdi,%rax
3749     3749:	f3 48 0f b8 c7       	popcnt %rdi,%rax
374e     374e:	48 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbp
3758     3758:	e8 00 00 00 00       	call   375d <.altinstr_replacement+0x375d>	3759: R_X86_64_PLT32	copy_user_generic_string-0x4
375d     375d:	e8 00 00 00 00       	call   3762 <.altinstr_replacement+0x3762>	375e: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
3762     3762:	48 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbp
376c     376c:	48 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbp
3776     3776:	e8 00 00 00 00       	call   377b <.altinstr_replacement+0x377b>	3777: R_X86_64_PLT32	copy_user_generic_string-0x4
377b     377b:	e8 00 00 00 00       	call   3780 <.altinstr_replacement+0x3780>	377c: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
3780     3780:	49 be 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r14
378a     378a:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
3794     3794:	0f 01 cb             	stac
3797     3797:	0f ae e8             	lfence
379a     379a:	0f 01 ca             	clac
379d     379d:	49 bf 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r15
37a7     37a7:	f3 0f b8 c7          	popcnt %edi,%eax
37ab     37ab:	f3 0f b8 c7          	popcnt %edi,%eax
37af     37af:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
37b9     37b9:	0f 01 cb             	stac
37bc     37bc:	0f ae e8             	lfence
37bf     37bf:	0f 01 ca             	clac
37c2     37c2:	0f 01 ca             	clac
37c5     37c5:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
37cf     37cf:	e8 00 00 00 00       	call   37d4 <.altinstr_replacement+0x37d4>	37d0: R_X86_64_PLT32	copy_user_generic_string-0x4
37d4     37d4:	e8 00 00 00 00       	call   37d9 <.altinstr_replacement+0x37d9>	37d5: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
37d9     37d9:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
37e3     37e3:	e8 00 00 00 00       	call   37e8 <.altinstr_replacement+0x37e8>	37e4: R_X86_64_PLT32	copy_user_generic_string-0x4
37e8     37e8:	e8 00 00 00 00       	call   37ed <.altinstr_replacement+0x37ed>	37e9: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
37ed     37ed:	f3 0f b8 c7          	popcnt %edi,%eax
37f1     37f1:	f3 0f b8 c7          	popcnt %edi,%eax
37f5     37f5:	e8 00 00 00 00       	call   37fa <.altinstr_replacement+0x37fa>	37f6: R_X86_64_PLT32	clear_page_rep-0x4
37fa     37fa:	e8 00 00 00 00       	call   37ff <.altinstr_replacement+0x37ff>	37fb: R_X86_64_PLT32	clear_page_erms-0x4
37ff     37ff:	9c                   	pushf
3800     3800:	58                   	pop    %rax
3801     3801:	9c                   	pushf
3802     3802:	58                   	pop    %rax
3803     3803:	9c                   	pushf
3804     3804:	58                   	pop    %rax
3805     3805:	9c                   	pushf
3806     3806:	58                   	pop    %rax
3807     3807:	9c                   	pushf
3808     3808:	58                   	pop    %rax
3809     3809:	9c                   	pushf
380a     380a:	58                   	pop    %rax
380b     380b:	9c                   	pushf
380c     380c:	58                   	pop    %rax
380d     380d:	9c                   	pushf
380e     380e:	58                   	pop    %rax
380f     380f:	9c                   	pushf
3810     3810:	58                   	pop    %rax
3811     3811:	fa                   	cli
3812     3812:	fb                   	sti
3813     3813:	9c                   	pushf
3814     3814:	58                   	pop    %rax
3815     3815:	fa                   	cli
3816     3816:	fb                   	sti
3817     3817:	9c                   	pushf
3818     3818:	58                   	pop    %rax
3819     3819:	fa                   	cli
381a     381a:	fb                   	sti
381b     381b:	9c                   	pushf
381c     381c:	58                   	pop    %rax
381d     381d:	fa                   	cli
381e     381e:	fb                   	sti
381f     381f:	9c                   	pushf
3820     3820:	58                   	pop    %rax
3821     3821:	fa                   	cli
3822     3822:	fb                   	sti
3823     3823:	9c                   	pushf
3824     3824:	58                   	pop    %rax
3825     3825:	fa                   	cli
3826     3826:	fb                   	sti
3827     3827:	9c                   	pushf
3828     3828:	58                   	pop    %rax
3829     3829:	fa                   	cli
382a     382a:	fb                   	sti
382b     382b:	9c                   	pushf
382c     382c:	58                   	pop    %rax
382d     382d:	fa                   	cli
382e     382e:	fb                   	sti
382f     382f:	9c                   	pushf
3830     3830:	58                   	pop    %rax
3831     3831:	fa                   	cli
3832     3832:	fb                   	sti
3833     3833:	9c                   	pushf
3834     3834:	58                   	pop    %rax
3835     3835:	fa                   	cli
3836     3836:	fb                   	sti
3837     3837:	9c                   	pushf
3838     3838:	58                   	pop    %rax
3839     3839:	fa                   	cli
383a     383a:	fb                   	sti
383b     383b:	9c                   	pushf
383c     383c:	58                   	pop    %rax
383d     383d:	fa                   	cli
383e     383e:	fb                   	sti
383f     383f:	9c                   	pushf
3840     3840:	58                   	pop    %rax
3841     3841:	fa                   	cli
3842     3842:	fb                   	sti
3843     3843:	9c                   	pushf
3844     3844:	58                   	pop    %rax
3845     3845:	fa                   	cli
3846     3846:	fb                   	sti
3847     3847:	9c                   	pushf
3848     3848:	58                   	pop    %rax
3849     3849:	fa                   	cli
384a     384a:	fb                   	sti
384b     384b:	9c                   	pushf
384c     384c:	58                   	pop    %rax
384d     384d:	fa                   	cli
384e     384e:	fb                   	sti
384f     384f:	9c                   	pushf
3850     3850:	58                   	pop    %rax
3851     3851:	fa                   	cli
3852     3852:	fb                   	sti
3853     3853:	9c                   	pushf
3854     3854:	58                   	pop    %rax
3855     3855:	fa                   	cli
3856     3856:	fb                   	sti
3857     3857:	9c                   	pushf
3858     3858:	58                   	pop    %rax
3859     3859:	fa                   	cli
385a     385a:	fb                   	sti
385b     385b:	9c                   	pushf
385c     385c:	58                   	pop    %rax
385d     385d:	fa                   	cli
385e     385e:	fb                   	sti
385f     385f:	9c                   	pushf
3860     3860:	58                   	pop    %rax
3861     3861:	fa                   	cli
3862     3862:	fb                   	sti
3863     3863:	9c                   	pushf
3864     3864:	58                   	pop    %rax
3865     3865:	fa                   	cli
3866     3866:	fb                   	sti
3867     3867:	9c                   	pushf
3868     3868:	58                   	pop    %rax
3869     3869:	fa                   	cli
386a     386a:	fb                   	sti
386b     386b:	9c                   	pushf
386c     386c:	58                   	pop    %rax
386d     386d:	fa                   	cli
386e     386e:	fb                   	sti
386f     386f:	9c                   	pushf
3870     3870:	58                   	pop    %rax
3871     3871:	fa                   	cli
3872     3872:	fb                   	sti
3873     3873:	9c                   	pushf
3874     3874:	58                   	pop    %rax
3875     3875:	fa                   	cli
3876     3876:	fb                   	sti
3877     3877:	9c                   	pushf
3878     3878:	58                   	pop    %rax
3879     3879:	fa                   	cli
387a     387a:	fb                   	sti
387b     387b:	9c                   	pushf
387c     387c:	58                   	pop    %rax
387d     387d:	fa                   	cli
387e     387e:	fb                   	sti
387f     387f:	9c                   	pushf
3880     3880:	58                   	pop    %rax
3881     3881:	fa                   	cli
3882     3882:	fb                   	sti
3883     3883:	9c                   	pushf
3884     3884:	58                   	pop    %rax
3885     3885:	fa                   	cli
3886     3886:	fb                   	sti
3887     3887:	9c                   	pushf
3888     3888:	58                   	pop    %rax
3889     3889:	fa                   	cli
388a     388a:	fb                   	sti
388b     388b:	9c                   	pushf
388c     388c:	58                   	pop    %rax
388d     388d:	fa                   	cli
388e     388e:	fb                   	sti
388f     388f:	9c                   	pushf
3890     3890:	58                   	pop    %rax
3891     3891:	fa                   	cli
3892     3892:	fb                   	sti
3893     3893:	9c                   	pushf
3894     3894:	58                   	pop    %rax
3895     3895:	fa                   	cli
3896     3896:	fb                   	sti
3897     3897:	9c                   	pushf
3898     3898:	58                   	pop    %rax
3899     3899:	fa                   	cli
389a     389a:	fb                   	sti
389b     389b:	9c                   	pushf
389c     389c:	58                   	pop    %rax
389d     389d:	fa                   	cli
389e     389e:	fb                   	sti
389f     389f:	9c                   	pushf
38a0     38a0:	58                   	pop    %rax
38a1     38a1:	fa                   	cli
38a2     38a2:	fb                   	sti
38a3     38a3:	9c                   	pushf
38a4     38a4:	58                   	pop    %rax
38a5     38a5:	fa                   	cli
38a6     38a6:	fb                   	sti
38a7     38a7:	9c                   	pushf
38a8     38a8:	58                   	pop    %rax
38a9     38a9:	fa                   	cli
38aa     38aa:	fb                   	sti
38ab     38ab:	9c                   	pushf
38ac     38ac:	58                   	pop    %rax
38ad     38ad:	fa                   	cli
38ae     38ae:	fb                   	sti
38af     38af:	9c                   	pushf
38b0     38b0:	58                   	pop    %rax
38b1     38b1:	fa                   	cli
38b2     38b2:	fb                   	sti
38b3     38b3:	9c                   	pushf
38b4     38b4:	58                   	pop    %rax
38b5     38b5:	fa                   	cli
38b6     38b6:	fb                   	sti
38b7     38b7:	9c                   	pushf
38b8     38b8:	58                   	pop    %rax
38b9     38b9:	fa                   	cli
38ba     38ba:	fb                   	sti
38bb     38bb:	9c                   	pushf
38bc     38bc:	58                   	pop    %rax
38bd     38bd:	fa                   	cli
38be     38be:	fb                   	sti
38bf     38bf:	9c                   	pushf
38c0     38c0:	58                   	pop    %rax
38c1     38c1:	fa                   	cli
38c2     38c2:	fb                   	sti
38c3     38c3:	9c                   	pushf
38c4     38c4:	58                   	pop    %rax
38c5     38c5:	fa                   	cli
38c6     38c6:	fb                   	sti
38c7     38c7:	9c                   	pushf
38c8     38c8:	58                   	pop    %rax
38c9     38c9:	fa                   	cli
38ca     38ca:	fb                   	sti
38cb     38cb:	9c                   	pushf
38cc     38cc:	58                   	pop    %rax
38cd     38cd:	fa                   	cli
38ce     38ce:	fb                   	sti
38cf     38cf:	9c                   	pushf
38d0     38d0:	58                   	pop    %rax
38d1     38d1:	fa                   	cli
38d2     38d2:	fb                   	sti
38d3     38d3:	9c                   	pushf
38d4     38d4:	58                   	pop    %rax
38d5     38d5:	fa                   	cli
38d6     38d6:	fb                   	sti
38d7     38d7:	9c                   	pushf
38d8     38d8:	58                   	pop    %rax
38d9     38d9:	fa                   	cli
38da     38da:	fb                   	sti
38db     38db:	9c                   	pushf
38dc     38dc:	58                   	pop    %rax
38dd     38dd:	fa                   	cli
38de     38de:	fb                   	sti
38df     38df:	9c                   	pushf
38e0     38e0:	58                   	pop    %rax
38e1     38e1:	fa                   	cli
38e2     38e2:	fb                   	sti
38e3     38e3:	9c                   	pushf
38e4     38e4:	58                   	pop    %rax
38e5     38e5:	fa                   	cli
38e6     38e6:	fb                   	sti
38e7     38e7:	9c                   	pushf
38e8     38e8:	58                   	pop    %rax
38e9     38e9:	fa                   	cli
38ea     38ea:	fb                   	sti
38eb     38eb:	9c                   	pushf
38ec     38ec:	58                   	pop    %rax
38ed     38ed:	fa                   	cli
38ee     38ee:	fb                   	sti
38ef     38ef:	9c                   	pushf
38f0     38f0:	58                   	pop    %rax
38f1     38f1:	fa                   	cli
38f2     38f2:	fb                   	sti
38f3     38f3:	9c                   	pushf
38f4     38f4:	58                   	pop    %rax
38f5     38f5:	fa                   	cli
38f6     38f6:	fb                   	sti
38f7     38f7:	9c                   	pushf
38f8     38f8:	58                   	pop    %rax
38f9     38f9:	fa                   	cli
38fa     38fa:	fb                   	sti
38fb     38fb:	9c                   	pushf
38fc     38fc:	58                   	pop    %rax
38fd     38fd:	fa                   	cli
38fe     38fe:	fb                   	sti
38ff     38ff:	9c                   	pushf
3900     3900:	58                   	pop    %rax
3901     3901:	fa                   	cli
3902     3902:	fb                   	sti
3903     3903:	9c                   	pushf
3904     3904:	58                   	pop    %rax
3905     3905:	fa                   	cli
3906     3906:	fb                   	sti
3907     3907:	9c                   	pushf
3908     3908:	58                   	pop    %rax
3909     3909:	fa                   	cli
390a     390a:	fb                   	sti
390b     390b:	9c                   	pushf
390c     390c:	58                   	pop    %rax
390d     390d:	fa                   	cli
390e     390e:	fb                   	sti
390f     390f:	9c                   	pushf
3910     3910:	58                   	pop    %rax
3911     3911:	fa                   	cli
3912     3912:	fb                   	sti
3913     3913:	9c                   	pushf
3914     3914:	58                   	pop    %rax
3915     3915:	fa                   	cli
3916     3916:	fb                   	sti
3917     3917:	9c                   	pushf
3918     3918:	58                   	pop    %rax
3919     3919:	fa                   	cli
391a     391a:	fb                   	sti
391b     391b:	9c                   	pushf
391c     391c:	58                   	pop    %rax
391d     391d:	fa                   	cli
391e     391e:	fb                   	sti
391f     391f:	9c                   	pushf
3920     3920:	58                   	pop    %rax
3921     3921:	fa                   	cli
3922     3922:	fb                   	sti
3923     3923:	9c                   	pushf
3924     3924:	58                   	pop    %rax
3925     3925:	fa                   	cli
3926     3926:	fb                   	sti
3927     3927:	9c                   	pushf
3928     3928:	58                   	pop    %rax
3929     3929:	fa                   	cli
392a     392a:	fb                   	sti
392b     392b:	9c                   	pushf
392c     392c:	58                   	pop    %rax
392d     392d:	fa                   	cli
392e     392e:	fb                   	sti
392f     392f:	9c                   	pushf
3930     3930:	58                   	pop    %rax
3931     3931:	fa                   	cli
3932     3932:	fb                   	sti
3933     3933:	9c                   	pushf
3934     3934:	58                   	pop    %rax
3935     3935:	fa                   	cli
3936     3936:	fb                   	sti
3937     3937:	9c                   	pushf
3938     3938:	58                   	pop    %rax
3939     3939:	fa                   	cli
393a     393a:	fb                   	sti
393b     393b:	9c                   	pushf
393c     393c:	58                   	pop    %rax
393d     393d:	fa                   	cli
393e     393e:	fb                   	sti
393f     393f:	9c                   	pushf
3940     3940:	58                   	pop    %rax
3941     3941:	fa                   	cli
3942     3942:	fb                   	sti
3943     3943:	9c                   	pushf
3944     3944:	58                   	pop    %rax
3945     3945:	fa                   	cli
3946     3946:	fb                   	sti
3947     3947:	9c                   	pushf
3948     3948:	58                   	pop    %rax
3949     3949:	fa                   	cli
394a     394a:	fb                   	sti
394b     394b:	9c                   	pushf
394c     394c:	58                   	pop    %rax
394d     394d:	fa                   	cli
394e     394e:	fb                   	sti
394f     394f:	9c                   	pushf
3950     3950:	58                   	pop    %rax
3951     3951:	fa                   	cli
3952     3952:	fb                   	sti
3953     3953:	9c                   	pushf
3954     3954:	58                   	pop    %rax
3955     3955:	fa                   	cli
3956     3956:	fb                   	sti
3957     3957:	9c                   	pushf
3958     3958:	58                   	pop    %rax
3959     3959:	fa                   	cli
395a     395a:	fb                   	sti
395b     395b:	9c                   	pushf
395c     395c:	58                   	pop    %rax
395d     395d:	fa                   	cli
395e     395e:	fb                   	sti
395f     395f:	9c                   	pushf
3960     3960:	58                   	pop    %rax
3961     3961:	fa                   	cli
3962     3962:	fb                   	sti
3963     3963:	9c                   	pushf
3964     3964:	58                   	pop    %rax
3965     3965:	fa                   	cli
3966     3966:	fb                   	sti
3967     3967:	9c                   	pushf
3968     3968:	58                   	pop    %rax
3969     3969:	fa                   	cli
396a     396a:	fb                   	sti
396b     396b:	9c                   	pushf
396c     396c:	58                   	pop    %rax
396d     396d:	fa                   	cli
396e     396e:	fb                   	sti
396f     396f:	9c                   	pushf
3970     3970:	58                   	pop    %rax
3971     3971:	fa                   	cli
3972     3972:	fb                   	sti
3973     3973:	9c                   	pushf
3974     3974:	58                   	pop    %rax
3975     3975:	fa                   	cli
3976     3976:	fb                   	sti
3977     3977:	9c                   	pushf
3978     3978:	58                   	pop    %rax
3979     3979:	fa                   	cli
397a     397a:	fb                   	sti
397b     397b:	9c                   	pushf
397c     397c:	58                   	pop    %rax
397d     397d:	fa                   	cli
397e     397e:	fb                   	sti
397f     397f:	9c                   	pushf
3980     3980:	58                   	pop    %rax
3981     3981:	fa                   	cli
3982     3982:	fb                   	sti
3983     3983:	9c                   	pushf
3984     3984:	58                   	pop    %rax
3985     3985:	fa                   	cli
3986     3986:	fb                   	sti
3987     3987:	9c                   	pushf
3988     3988:	58                   	pop    %rax
3989     3989:	fa                   	cli
398a     398a:	fb                   	sti
398b     398b:	9c                   	pushf
398c     398c:	58                   	pop    %rax
398d     398d:	fa                   	cli
398e     398e:	fb                   	sti
398f     398f:	9c                   	pushf
3990     3990:	58                   	pop    %rax
3991     3991:	fa                   	cli
3992     3992:	fb                   	sti
3993     3993:	9c                   	pushf
3994     3994:	58                   	pop    %rax
3995     3995:	fa                   	cli
3996     3996:	fb                   	sti
3997     3997:	9c                   	pushf
3998     3998:	58                   	pop    %rax
3999     3999:	fa                   	cli
399a     399a:	fb                   	sti
399b     399b:	9c                   	pushf
399c     399c:	58                   	pop    %rax
399d     399d:	fa                   	cli
399e     399e:	fb                   	sti
399f     399f:	9c                   	pushf
39a0     39a0:	58                   	pop    %rax
39a1     39a1:	fa                   	cli
39a2     39a2:	fb                   	sti
39a3     39a3:	9c                   	pushf
39a4     39a4:	58                   	pop    %rax
39a5     39a5:	fa                   	cli
39a6     39a6:	fb                   	sti
39a7     39a7:	9c                   	pushf
39a8     39a8:	58                   	pop    %rax
39a9     39a9:	fa                   	cli
39aa     39aa:	fb                   	sti
39ab     39ab:	9c                   	pushf
39ac     39ac:	58                   	pop    %rax
39ad     39ad:	fa                   	cli
39ae     39ae:	fb                   	sti
39af     39af:	9c                   	pushf
39b0     39b0:	58                   	pop    %rax
39b1     39b1:	fa                   	cli
39b2     39b2:	fb                   	sti
39b3     39b3:	9c                   	pushf
39b4     39b4:	58                   	pop    %rax
39b5     39b5:	fa                   	cli
39b6     39b6:	fb                   	sti
39b7     39b7:	9c                   	pushf
39b8     39b8:	58                   	pop    %rax
39b9     39b9:	fa                   	cli
39ba     39ba:	fb                   	sti
39bb     39bb:	9c                   	pushf
39bc     39bc:	58                   	pop    %rax
39bd     39bd:	fa                   	cli
39be     39be:	fb                   	sti
39bf     39bf:	9c                   	pushf
39c0     39c0:	58                   	pop    %rax
39c1     39c1:	fa                   	cli
39c2     39c2:	fb                   	sti
39c3     39c3:	9c                   	pushf
39c4     39c4:	58                   	pop    %rax
39c5     39c5:	fa                   	cli
39c6     39c6:	fb                   	sti
39c7     39c7:	9c                   	pushf
39c8     39c8:	58                   	pop    %rax
39c9     39c9:	fa                   	cli
39ca     39ca:	fb                   	sti
39cb     39cb:	9c                   	pushf
39cc     39cc:	58                   	pop    %rax
39cd     39cd:	fa                   	cli
39ce     39ce:	fb                   	sti
39cf     39cf:	9c                   	pushf
39d0     39d0:	58                   	pop    %rax
39d1     39d1:	fa                   	cli
39d2     39d2:	fb                   	sti
39d3     39d3:	9c                   	pushf
39d4     39d4:	58                   	pop    %rax
39d5     39d5:	fa                   	cli
39d6     39d6:	fb                   	sti
39d7     39d7:	9c                   	pushf
39d8     39d8:	58                   	pop    %rax
39d9     39d9:	fa                   	cli
39da     39da:	fb                   	sti
39db     39db:	9c                   	pushf
39dc     39dc:	58                   	pop    %rax
39dd     39dd:	fa                   	cli
39de     39de:	fb                   	sti
39df     39df:	9c                   	pushf
39e0     39e0:	58                   	pop    %rax
39e1     39e1:	fa                   	cli
39e2     39e2:	fb                   	sti
39e3     39e3:	9c                   	pushf
39e4     39e4:	58                   	pop    %rax
39e5     39e5:	fa                   	cli
39e6     39e6:	fb                   	sti
39e7     39e7:	9c                   	pushf
39e8     39e8:	58                   	pop    %rax
39e9     39e9:	fa                   	cli
39ea     39ea:	fb                   	sti
39eb     39eb:	9c                   	pushf
39ec     39ec:	58                   	pop    %rax
39ed     39ed:	fa                   	cli
39ee     39ee:	fb                   	sti
39ef     39ef:	9c                   	pushf
39f0     39f0:	58                   	pop    %rax
39f1     39f1:	fa                   	cli
39f2     39f2:	fb                   	sti
39f3     39f3:	9c                   	pushf
39f4     39f4:	58                   	pop    %rax
39f5     39f5:	fa                   	cli
39f6     39f6:	fb                   	sti
39f7     39f7:	9c                   	pushf
39f8     39f8:	58                   	pop    %rax
39f9     39f9:	fa                   	cli
39fa     39fa:	fb                   	sti
39fb     39fb:	9c                   	pushf
39fc     39fc:	58                   	pop    %rax
39fd     39fd:	fa                   	cli
39fe     39fe:	fb                   	sti
39ff     39ff:	9c                   	pushf
3a00     3a00:	58                   	pop    %rax
3a01     3a01:	fa                   	cli
3a02     3a02:	fb                   	sti
3a03     3a03:	9c                   	pushf
3a04     3a04:	58                   	pop    %rax
3a05     3a05:	fa                   	cli
3a06     3a06:	fb                   	sti
3a07     3a07:	9c                   	pushf
3a08     3a08:	58                   	pop    %rax
3a09     3a09:	fa                   	cli
3a0a     3a0a:	fb                   	sti
3a0b     3a0b:	9c                   	pushf
3a0c     3a0c:	58                   	pop    %rax
3a0d     3a0d:	fa                   	cli
3a0e     3a0e:	fb                   	sti
3a0f     3a0f:	9c                   	pushf
3a10     3a10:	58                   	pop    %rax
3a11     3a11:	fa                   	cli
3a12     3a12:	fb                   	sti
3a13     3a13:	9c                   	pushf
3a14     3a14:	58                   	pop    %rax
3a15     3a15:	fa                   	cli
3a16     3a16:	fb                   	sti
3a17     3a17:	9c                   	pushf
3a18     3a18:	58                   	pop    %rax
3a19     3a19:	fa                   	cli
3a1a     3a1a:	fb                   	sti
3a1b     3a1b:	9c                   	pushf
3a1c     3a1c:	58                   	pop    %rax
3a1d     3a1d:	fa                   	cli
3a1e     3a1e:	fb                   	sti
3a1f     3a1f:	9c                   	pushf
3a20     3a20:	58                   	pop    %rax
3a21     3a21:	fa                   	cli
3a22     3a22:	fb                   	sti
3a23     3a23:	9c                   	pushf
3a24     3a24:	58                   	pop    %rax
3a25     3a25:	fa                   	cli
3a26     3a26:	fb                   	sti
3a27     3a27:	9c                   	pushf
3a28     3a28:	58                   	pop    %rax
3a29     3a29:	fa                   	cli
3a2a     3a2a:	fb                   	sti
3a2b     3a2b:	9c                   	pushf
3a2c     3a2c:	58                   	pop    %rax
3a2d     3a2d:	fa                   	cli
3a2e     3a2e:	fb                   	sti
3a2f     3a2f:	9c                   	pushf
3a30     3a30:	58                   	pop    %rax
3a31     3a31:	fa                   	cli
3a32     3a32:	fb                   	sti
3a33     3a33:	9c                   	pushf
3a34     3a34:	58                   	pop    %rax
3a35     3a35:	fa                   	cli
3a36     3a36:	fb                   	sti
3a37     3a37:	9c                   	pushf
3a38     3a38:	58                   	pop    %rax
3a39     3a39:	fa                   	cli
3a3a     3a3a:	fb                   	sti
3a3b     3a3b:	9c                   	pushf
3a3c     3a3c:	58                   	pop    %rax
3a3d     3a3d:	fa                   	cli
3a3e     3a3e:	fb                   	sti
3a3f     3a3f:	9c                   	pushf
3a40     3a40:	58                   	pop    %rax
3a41     3a41:	fa                   	cli
3a42     3a42:	fb                   	sti
3a43     3a43:	9c                   	pushf
3a44     3a44:	58                   	pop    %rax
3a45     3a45:	fa                   	cli
3a46     3a46:	fb                   	sti
3a47     3a47:	9c                   	pushf
3a48     3a48:	58                   	pop    %rax
3a49     3a49:	fa                   	cli
3a4a     3a4a:	fb                   	sti
3a4b     3a4b:	9c                   	pushf
3a4c     3a4c:	58                   	pop    %rax
3a4d     3a4d:	fa                   	cli
3a4e     3a4e:	fb                   	sti
3a4f     3a4f:	9c                   	pushf
3a50     3a50:	58                   	pop    %rax
3a51     3a51:	fa                   	cli
3a52     3a52:	fb                   	sti
3a53     3a53:	9c                   	pushf
3a54     3a54:	58                   	pop    %rax
3a55     3a55:	fa                   	cli
3a56     3a56:	fb                   	sti
3a57     3a57:	9c                   	pushf
3a58     3a58:	58                   	pop    %rax
3a59     3a59:	fa                   	cli
3a5a     3a5a:	fb                   	sti
3a5b     3a5b:	9c                   	pushf
3a5c     3a5c:	58                   	pop    %rax
3a5d     3a5d:	fa                   	cli
3a5e     3a5e:	fb                   	sti
3a5f     3a5f:	9c                   	pushf
3a60     3a60:	58                   	pop    %rax
3a61     3a61:	fa                   	cli
3a62     3a62:	fb                   	sti
3a63     3a63:	9c                   	pushf
3a64     3a64:	58                   	pop    %rax
3a65     3a65:	fa                   	cli
3a66     3a66:	fb                   	sti
3a67     3a67:	9c                   	pushf
3a68     3a68:	58                   	pop    %rax
3a69     3a69:	fa                   	cli
3a6a     3a6a:	fb                   	sti
3a6b     3a6b:	9c                   	pushf
3a6c     3a6c:	58                   	pop    %rax
3a6d     3a6d:	fa                   	cli
3a6e     3a6e:	fb                   	sti
3a6f     3a6f:	9c                   	pushf
3a70     3a70:	58                   	pop    %rax
3a71     3a71:	fa                   	cli
3a72     3a72:	fb                   	sti
3a73     3a73:	9c                   	pushf
3a74     3a74:	58                   	pop    %rax
3a75     3a75:	fa                   	cli
3a76     3a76:	fb                   	sti
3a77     3a77:	9c                   	pushf
3a78     3a78:	58                   	pop    %rax
3a79     3a79:	fa                   	cli
3a7a     3a7a:	fb                   	sti
3a7b     3a7b:	9c                   	pushf
3a7c     3a7c:	58                   	pop    %rax
3a7d     3a7d:	fa                   	cli
3a7e     3a7e:	fb                   	sti
3a7f     3a7f:	9c                   	pushf
3a80     3a80:	58                   	pop    %rax
3a81     3a81:	fa                   	cli
3a82     3a82:	fb                   	sti
3a83     3a83:	9c                   	pushf
3a84     3a84:	58                   	pop    %rax
3a85     3a85:	fa                   	cli
3a86     3a86:	fb                   	sti
3a87     3a87:	9c                   	pushf
3a88     3a88:	58                   	pop    %rax
3a89     3a89:	fa                   	cli
3a8a     3a8a:	fb                   	sti
3a8b     3a8b:	9c                   	pushf
3a8c     3a8c:	58                   	pop    %rax
3a8d     3a8d:	fa                   	cli
3a8e     3a8e:	fb                   	sti
3a8f     3a8f:	9c                   	pushf
3a90     3a90:	58                   	pop    %rax
3a91     3a91:	fa                   	cli
3a92     3a92:	fb                   	sti
3a93     3a93:	9c                   	pushf
3a94     3a94:	58                   	pop    %rax
3a95     3a95:	fa                   	cli
3a96     3a96:	fb                   	sti
3a97     3a97:	9c                   	pushf
3a98     3a98:	58                   	pop    %rax
3a99     3a99:	fa                   	cli
3a9a     3a9a:	fb                   	sti
3a9b     3a9b:	9c                   	pushf
3a9c     3a9c:	58                   	pop    %rax
3a9d     3a9d:	fa                   	cli
3a9e     3a9e:	fb                   	sti
3a9f     3a9f:	9c                   	pushf
3aa0     3aa0:	58                   	pop    %rax
3aa1     3aa1:	fa                   	cli
3aa2     3aa2:	fb                   	sti
3aa3     3aa3:	9c                   	pushf
3aa4     3aa4:	58                   	pop    %rax
3aa5     3aa5:	fa                   	cli
3aa6     3aa6:	fb                   	sti
3aa7     3aa7:	9c                   	pushf
3aa8     3aa8:	58                   	pop    %rax
3aa9     3aa9:	fa                   	cli
3aaa     3aaa:	fb                   	sti
3aab     3aab:	9c                   	pushf
3aac     3aac:	58                   	pop    %rax
3aad     3aad:	fa                   	cli
3aae     3aae:	fb                   	sti
3aaf     3aaf:	9c                   	pushf
3ab0     3ab0:	58                   	pop    %rax
3ab1     3ab1:	fa                   	cli
3ab2     3ab2:	fb                   	sti
3ab3     3ab3:	9c                   	pushf
3ab4     3ab4:	58                   	pop    %rax
3ab5     3ab5:	fa                   	cli
3ab6     3ab6:	fb                   	sti
3ab7     3ab7:	9c                   	pushf
3ab8     3ab8:	58                   	pop    %rax
3ab9     3ab9:	fa                   	cli
3aba     3aba:	fb                   	sti
3abb     3abb:	9c                   	pushf
3abc     3abc:	58                   	pop    %rax
3abd     3abd:	fa                   	cli
3abe     3abe:	fb                   	sti
3abf     3abf:	9c                   	pushf
3ac0     3ac0:	58                   	pop    %rax
3ac1     3ac1:	fa                   	cli
3ac2     3ac2:	fb                   	sti
3ac3     3ac3:	9c                   	pushf
3ac4     3ac4:	58                   	pop    %rax
3ac5     3ac5:	fa                   	cli
3ac6     3ac6:	fb                   	sti
3ac7     3ac7:	9c                   	pushf
3ac8     3ac8:	58                   	pop    %rax
3ac9     3ac9:	fa                   	cli
3aca     3aca:	fb                   	sti
3acb     3acb:	9c                   	pushf
3acc     3acc:	58                   	pop    %rax
3acd     3acd:	fa                   	cli
3ace     3ace:	fb                   	sti
3acf     3acf:	9c                   	pushf
3ad0     3ad0:	58                   	pop    %rax
3ad1     3ad1:	fa                   	cli
3ad2     3ad2:	fb                   	sti
3ad3     3ad3:	9c                   	pushf
3ad4     3ad4:	58                   	pop    %rax
3ad5     3ad5:	fa                   	cli
3ad6     3ad6:	fb                   	sti
3ad7     3ad7:	9c                   	pushf
3ad8     3ad8:	58                   	pop    %rax
3ad9     3ad9:	fa                   	cli
3ada     3ada:	fb                   	sti
3adb     3adb:	9c                   	pushf
3adc     3adc:	58                   	pop    %rax
3add     3add:	fa                   	cli
3ade     3ade:	fb                   	sti
3adf     3adf:	9c                   	pushf
3ae0     3ae0:	58                   	pop    %rax
3ae1     3ae1:	fa                   	cli
3ae2     3ae2:	fb                   	sti
3ae3     3ae3:	9c                   	pushf
3ae4     3ae4:	58                   	pop    %rax
3ae5     3ae5:	fa                   	cli
3ae6     3ae6:	fb                   	sti
3ae7     3ae7:	9c                   	pushf
3ae8     3ae8:	58                   	pop    %rax
3ae9     3ae9:	fa                   	cli
3aea     3aea:	fb                   	sti
3aeb     3aeb:	9c                   	pushf
3aec     3aec:	58                   	pop    %rax
3aed     3aed:	fa                   	cli
3aee     3aee:	fb                   	sti
3aef     3aef:	9c                   	pushf
3af0     3af0:	58                   	pop    %rax
3af1     3af1:	fa                   	cli
3af2     3af2:	fb                   	sti
3af3     3af3:	9c                   	pushf
3af4     3af4:	58                   	pop    %rax
3af5     3af5:	fa                   	cli
3af6     3af6:	fb                   	sti
3af7     3af7:	9c                   	pushf
3af8     3af8:	58                   	pop    %rax
3af9     3af9:	fa                   	cli
3afa     3afa:	fb                   	sti
3afb     3afb:	9c                   	pushf
3afc     3afc:	58                   	pop    %rax
3afd     3afd:	fa                   	cli
3afe     3afe:	fb                   	sti
3aff     3aff:	9c                   	pushf
3b00     3b00:	58                   	pop    %rax
3b01     3b01:	fa                   	cli
3b02     3b02:	fb                   	sti
3b03     3b03:	9c                   	pushf
3b04     3b04:	58                   	pop    %rax
3b05     3b05:	fa                   	cli
3b06     3b06:	fb                   	sti
3b07     3b07:	9c                   	pushf
3b08     3b08:	58                   	pop    %rax
3b09     3b09:	fa                   	cli
3b0a     3b0a:	fb                   	sti
3b0b     3b0b:	9c                   	pushf
3b0c     3b0c:	58                   	pop    %rax
3b0d     3b0d:	fa                   	cli
3b0e     3b0e:	fb                   	sti
3b0f     3b0f:	9c                   	pushf
3b10     3b10:	58                   	pop    %rax
3b11     3b11:	fa                   	cli
3b12     3b12:	fb                   	sti
3b13     3b13:	9c                   	pushf
3b14     3b14:	58                   	pop    %rax
3b15     3b15:	fa                   	cli
3b16     3b16:	fb                   	sti
3b17     3b17:	9c                   	pushf
3b18     3b18:	58                   	pop    %rax
3b19     3b19:	fa                   	cli
3b1a     3b1a:	fb                   	sti
3b1b     3b1b:	9c                   	pushf
3b1c     3b1c:	58                   	pop    %rax
3b1d     3b1d:	fa                   	cli
3b1e     3b1e:	fb                   	sti
3b1f     3b1f:	9c                   	pushf
3b20     3b20:	58                   	pop    %rax
3b21     3b21:	fa                   	cli
3b22     3b22:	fb                   	sti
3b23     3b23:	9c                   	pushf
3b24     3b24:	58                   	pop    %rax
3b25     3b25:	fa                   	cli
3b26     3b26:	fb                   	sti
3b27     3b27:	9c                   	pushf
3b28     3b28:	58                   	pop    %rax
3b29     3b29:	fa                   	cli
3b2a     3b2a:	fb                   	sti
3b2b     3b2b:	9c                   	pushf
3b2c     3b2c:	58                   	pop    %rax
3b2d     3b2d:	fa                   	cli
3b2e     3b2e:	fb                   	sti
3b2f     3b2f:	9c                   	pushf
3b30     3b30:	58                   	pop    %rax
3b31     3b31:	fa                   	cli
3b32     3b32:	fb                   	sti
3b33     3b33:	9c                   	pushf
3b34     3b34:	58                   	pop    %rax
3b35     3b35:	fa                   	cli
3b36     3b36:	fb                   	sti
3b37     3b37:	9c                   	pushf
3b38     3b38:	58                   	pop    %rax
3b39     3b39:	fa                   	cli
3b3a     3b3a:	fb                   	sti
3b3b     3b3b:	9c                   	pushf
3b3c     3b3c:	58                   	pop    %rax
3b3d     3b3d:	fa                   	cli
3b3e     3b3e:	fb                   	sti
3b3f     3b3f:	9c                   	pushf
3b40     3b40:	58                   	pop    %rax
3b41     3b41:	fa                   	cli
3b42     3b42:	fb                   	sti
3b43     3b43:	9c                   	pushf
3b44     3b44:	58                   	pop    %rax
3b45     3b45:	fa                   	cli
3b46     3b46:	fb                   	sti
3b47     3b47:	9c                   	pushf
3b48     3b48:	58                   	pop    %rax
3b49     3b49:	fa                   	cli
3b4a     3b4a:	fb                   	sti
3b4b     3b4b:	9c                   	pushf
3b4c     3b4c:	58                   	pop    %rax
3b4d     3b4d:	fa                   	cli
3b4e     3b4e:	fb                   	sti
3b4f     3b4f:	9c                   	pushf
3b50     3b50:	58                   	pop    %rax
3b51     3b51:	fa                   	cli
3b52     3b52:	fb                   	sti
3b53     3b53:	9c                   	pushf
3b54     3b54:	58                   	pop    %rax
3b55     3b55:	fa                   	cli
3b56     3b56:	fb                   	sti
3b57     3b57:	9c                   	pushf
3b58     3b58:	58                   	pop    %rax
3b59     3b59:	fa                   	cli
3b5a     3b5a:	fb                   	sti
3b5b     3b5b:	9c                   	pushf
3b5c     3b5c:	58                   	pop    %rax
3b5d     3b5d:	fa                   	cli
3b5e     3b5e:	fb                   	sti
3b5f     3b5f:	9c                   	pushf
3b60     3b60:	58                   	pop    %rax
3b61     3b61:	fa                   	cli
3b62     3b62:	fb                   	sti
3b63     3b63:	9c                   	pushf
3b64     3b64:	58                   	pop    %rax
3b65     3b65:	fa                   	cli
3b66     3b66:	fb                   	sti
3b67     3b67:	9c                   	pushf
3b68     3b68:	58                   	pop    %rax
3b69     3b69:	fa                   	cli
3b6a     3b6a:	fb                   	sti
3b6b     3b6b:	9c                   	pushf
3b6c     3b6c:	58                   	pop    %rax
3b6d     3b6d:	fa                   	cli
3b6e     3b6e:	fb                   	sti
3b6f     3b6f:	9c                   	pushf
3b70     3b70:	58                   	pop    %rax
3b71     3b71:	fa                   	cli
3b72     3b72:	fb                   	sti
3b73     3b73:	9c                   	pushf
3b74     3b74:	58                   	pop    %rax
3b75     3b75:	fa                   	cli
3b76     3b76:	fb                   	sti
3b77     3b77:	9c                   	pushf
3b78     3b78:	58                   	pop    %rax
3b79     3b79:	fa                   	cli
3b7a     3b7a:	fb                   	sti
3b7b     3b7b:	9c                   	pushf
3b7c     3b7c:	58                   	pop    %rax
3b7d     3b7d:	fa                   	cli
3b7e     3b7e:	fb                   	sti
3b7f     3b7f:	9c                   	pushf
3b80     3b80:	58                   	pop    %rax
3b81     3b81:	fa                   	cli
3b82     3b82:	fb                   	sti
3b83     3b83:	9c                   	pushf
3b84     3b84:	58                   	pop    %rax
3b85     3b85:	fa                   	cli
3b86     3b86:	fb                   	sti
3b87     3b87:	9c                   	pushf
3b88     3b88:	58                   	pop    %rax
3b89     3b89:	fa                   	cli
3b8a     3b8a:	fb                   	sti
3b8b     3b8b:	9c                   	pushf
3b8c     3b8c:	58                   	pop    %rax
3b8d     3b8d:	fa                   	cli
3b8e     3b8e:	fb                   	sti
3b8f     3b8f:	9c                   	pushf
3b90     3b90:	58                   	pop    %rax
3b91     3b91:	fa                   	cli
3b92     3b92:	fb                   	sti
3b93     3b93:	9c                   	pushf
3b94     3b94:	58                   	pop    %rax
3b95     3b95:	fa                   	cli
3b96     3b96:	fb                   	sti
3b97     3b97:	9c                   	pushf
3b98     3b98:	58                   	pop    %rax
3b99     3b99:	fa                   	cli
3b9a     3b9a:	fb                   	sti
3b9b     3b9b:	9c                   	pushf
3b9c     3b9c:	58                   	pop    %rax
3b9d     3b9d:	fa                   	cli
3b9e     3b9e:	fb                   	sti
3b9f     3b9f:	9c                   	pushf
3ba0     3ba0:	58                   	pop    %rax
3ba1     3ba1:	fa                   	cli
3ba2     3ba2:	fb                   	sti
3ba3     3ba3:	9c                   	pushf
3ba4     3ba4:	58                   	pop    %rax
3ba5     3ba5:	fa                   	cli
3ba6     3ba6:	fb                   	sti
3ba7     3ba7:	9c                   	pushf
3ba8     3ba8:	58                   	pop    %rax
3ba9     3ba9:	fa                   	cli
3baa     3baa:	fb                   	sti
3bab     3bab:	9c                   	pushf
3bac     3bac:	58                   	pop    %rax
3bad     3bad:	fa                   	cli
3bae     3bae:	fb                   	sti
3baf     3baf:	9c                   	pushf
3bb0     3bb0:	58                   	pop    %rax
3bb1     3bb1:	fa                   	cli
3bb2     3bb2:	fb                   	sti
3bb3     3bb3:	9c                   	pushf
3bb4     3bb4:	58                   	pop    %rax
3bb5     3bb5:	fa                   	cli
3bb6     3bb6:	fb                   	sti
3bb7     3bb7:	9c                   	pushf
3bb8     3bb8:	58                   	pop    %rax
3bb9     3bb9:	fa                   	cli
3bba     3bba:	fb                   	sti
3bbb     3bbb:	9c                   	pushf
3bbc     3bbc:	58                   	pop    %rax
3bbd     3bbd:	fa                   	cli
3bbe     3bbe:	fb                   	sti
3bbf     3bbf:	9c                   	pushf
3bc0     3bc0:	58                   	pop    %rax
3bc1     3bc1:	fa                   	cli
3bc2     3bc2:	fb                   	sti
3bc3     3bc3:	9c                   	pushf
3bc4     3bc4:	58                   	pop    %rax
3bc5     3bc5:	fa                   	cli
3bc6     3bc6:	fb                   	sti
3bc7     3bc7:	9c                   	pushf
3bc8     3bc8:	58                   	pop    %rax
3bc9     3bc9:	fa                   	cli
3bca     3bca:	fb                   	sti
3bcb     3bcb:	9c                   	pushf
3bcc     3bcc:	58                   	pop    %rax
3bcd     3bcd:	fa                   	cli
3bce     3bce:	fb                   	sti
3bcf     3bcf:	9c                   	pushf
3bd0     3bd0:	58                   	pop    %rax
3bd1     3bd1:	fa                   	cli
3bd2     3bd2:	fb                   	sti
3bd3     3bd3:	9c                   	pushf
3bd4     3bd4:	58                   	pop    %rax
3bd5     3bd5:	fa                   	cli
3bd6     3bd6:	fb                   	sti
3bd7     3bd7:	9c                   	pushf
3bd8     3bd8:	58                   	pop    %rax
3bd9     3bd9:	fa                   	cli
3bda     3bda:	fb                   	sti
3bdb     3bdb:	9c                   	pushf
3bdc     3bdc:	58                   	pop    %rax
3bdd     3bdd:	fa                   	cli
3bde     3bde:	fb                   	sti
3bdf     3bdf:	9c                   	pushf
3be0     3be0:	58                   	pop    %rax
3be1     3be1:	fa                   	cli
3be2     3be2:	fb                   	sti
3be3     3be3:	9c                   	pushf
3be4     3be4:	58                   	pop    %rax
3be5     3be5:	fa                   	cli
3be6     3be6:	fb                   	sti
3be7     3be7:	9c                   	pushf
3be8     3be8:	58                   	pop    %rax
3be9     3be9:	fa                   	cli
3bea     3bea:	fb                   	sti
3beb     3beb:	9c                   	pushf
3bec     3bec:	58                   	pop    %rax
3bed     3bed:	fa                   	cli
3bee     3bee:	fb                   	sti
3bef     3bef:	9c                   	pushf
3bf0     3bf0:	58                   	pop    %rax
3bf1     3bf1:	fa                   	cli
3bf2     3bf2:	fb                   	sti
3bf3     3bf3:	9c                   	pushf
3bf4     3bf4:	58                   	pop    %rax
3bf5     3bf5:	fa                   	cli
3bf6     3bf6:	fb                   	sti
3bf7     3bf7:	9c                   	pushf
3bf8     3bf8:	58                   	pop    %rax
3bf9     3bf9:	fa                   	cli
3bfa     3bfa:	fb                   	sti
3bfb     3bfb:	9c                   	pushf
3bfc     3bfc:	58                   	pop    %rax
3bfd     3bfd:	fa                   	cli
3bfe     3bfe:	fb                   	sti
3bff     3bff:	9c                   	pushf
3c00     3c00:	58                   	pop    %rax
3c01     3c01:	fa                   	cli
3c02     3c02:	fb                   	sti
3c03     3c03:	9c                   	pushf
3c04     3c04:	58                   	pop    %rax
3c05     3c05:	fa                   	cli
3c06     3c06:	fb                   	sti
3c07     3c07:	9c                   	pushf
3c08     3c08:	58                   	pop    %rax
3c09     3c09:	fa                   	cli
3c0a     3c0a:	fb                   	sti
3c0b     3c0b:	9c                   	pushf
3c0c     3c0c:	58                   	pop    %rax
3c0d     3c0d:	fa                   	cli
3c0e     3c0e:	fb                   	sti
3c0f     3c0f:	9c                   	pushf
3c10     3c10:	58                   	pop    %rax
3c11     3c11:	fa                   	cli
3c12     3c12:	fb                   	sti
3c13     3c13:	9c                   	pushf
3c14     3c14:	58                   	pop    %rax
3c15     3c15:	fa                   	cli
3c16     3c16:	fb                   	sti
3c17     3c17:	9c                   	pushf
3c18     3c18:	58                   	pop    %rax
3c19     3c19:	fa                   	cli
3c1a     3c1a:	fb                   	sti
3c1b     3c1b:	9c                   	pushf
3c1c     3c1c:	58                   	pop    %rax
3c1d     3c1d:	fa                   	cli
3c1e     3c1e:	fb                   	sti
3c1f     3c1f:	9c                   	pushf
3c20     3c20:	58                   	pop    %rax
3c21     3c21:	fa                   	cli
3c22     3c22:	fb                   	sti
3c23     3c23:	9c                   	pushf
3c24     3c24:	58                   	pop    %rax
3c25     3c25:	fa                   	cli
3c26     3c26:	fb                   	sti
3c27     3c27:	9c                   	pushf
3c28     3c28:	58                   	pop    %rax
3c29     3c29:	fa                   	cli
3c2a     3c2a:	fb                   	sti
3c2b     3c2b:	9c                   	pushf
3c2c     3c2c:	58                   	pop    %rax
3c2d     3c2d:	fa                   	cli
3c2e     3c2e:	fb                   	sti
3c2f     3c2f:	9c                   	pushf
3c30     3c30:	58                   	pop    %rax
3c31     3c31:	fa                   	cli
3c32     3c32:	fb                   	sti
3c33     3c33:	9c                   	pushf
3c34     3c34:	58                   	pop    %rax
3c35     3c35:	fa                   	cli
3c36     3c36:	fb                   	sti
3c37     3c37:	9c                   	pushf
3c38     3c38:	58                   	pop    %rax
3c39     3c39:	fa                   	cli
3c3a     3c3a:	fb                   	sti
3c3b     3c3b:	9c                   	pushf
3c3c     3c3c:	58                   	pop    %rax
3c3d     3c3d:	fa                   	cli
3c3e     3c3e:	fb                   	sti
3c3f     3c3f:	9c                   	pushf
3c40     3c40:	58                   	pop    %rax
3c41     3c41:	fa                   	cli
3c42     3c42:	fb                   	sti
3c43     3c43:	9c                   	pushf
3c44     3c44:	58                   	pop    %rax
3c45     3c45:	fa                   	cli
3c46     3c46:	fb                   	sti
3c47     3c47:	9c                   	pushf
3c48     3c48:	58                   	pop    %rax
3c49     3c49:	fa                   	cli
3c4a     3c4a:	fb                   	sti
3c4b     3c4b:	9c                   	pushf
3c4c     3c4c:	58                   	pop    %rax
3c4d     3c4d:	fa                   	cli
3c4e     3c4e:	fb                   	sti
3c4f     3c4f:	9c                   	pushf
3c50     3c50:	58                   	pop    %rax
3c51     3c51:	fa                   	cli
3c52     3c52:	fb                   	sti
3c53     3c53:	9c                   	pushf
3c54     3c54:	58                   	pop    %rax
3c55     3c55:	fa                   	cli
3c56     3c56:	fb                   	sti
3c57     3c57:	9c                   	pushf
3c58     3c58:	58                   	pop    %rax
3c59     3c59:	fa                   	cli
3c5a     3c5a:	fb                   	sti
3c5b     3c5b:	9c                   	pushf
3c5c     3c5c:	58                   	pop    %rax
3c5d     3c5d:	fa                   	cli
3c5e     3c5e:	fb                   	sti
3c5f     3c5f:	9c                   	pushf
3c60     3c60:	58                   	pop    %rax
3c61     3c61:	fa                   	cli
3c62     3c62:	fb                   	sti
3c63     3c63:	9c                   	pushf
3c64     3c64:	58                   	pop    %rax
3c65     3c65:	fa                   	cli
3c66     3c66:	fb                   	sti
3c67     3c67:	9c                   	pushf
3c68     3c68:	58                   	pop    %rax
3c69     3c69:	fa                   	cli
3c6a     3c6a:	fb                   	sti
3c6b     3c6b:	9c                   	pushf
3c6c     3c6c:	58                   	pop    %rax
3c6d     3c6d:	fa                   	cli
3c6e     3c6e:	fb                   	sti
3c6f     3c6f:	9c                   	pushf
3c70     3c70:	58                   	pop    %rax
3c71     3c71:	fa                   	cli
3c72     3c72:	fb                   	sti
3c73     3c73:	9c                   	pushf
3c74     3c74:	58                   	pop    %rax
3c75     3c75:	fa                   	cli
3c76     3c76:	fb                   	sti
3c77     3c77:	9c                   	pushf
3c78     3c78:	58                   	pop    %rax
3c79     3c79:	fa                   	cli
3c7a     3c7a:	fb                   	sti
3c7b     3c7b:	9c                   	pushf
3c7c     3c7c:	58                   	pop    %rax
3c7d     3c7d:	fa                   	cli
3c7e     3c7e:	fb                   	sti
3c7f     3c7f:	9c                   	pushf
3c80     3c80:	58                   	pop    %rax
3c81     3c81:	fa                   	cli
3c82     3c82:	fb                   	sti
3c83     3c83:	9c                   	pushf
3c84     3c84:	58                   	pop    %rax
3c85     3c85:	fa                   	cli
3c86     3c86:	fb                   	sti
3c87     3c87:	9c                   	pushf
3c88     3c88:	58                   	pop    %rax
3c89     3c89:	fa                   	cli
3c8a     3c8a:	fb                   	sti
3c8b     3c8b:	9c                   	pushf
3c8c     3c8c:	58                   	pop    %rax
3c8d     3c8d:	fa                   	cli
3c8e     3c8e:	fb                   	sti
3c8f     3c8f:	9c                   	pushf
3c90     3c90:	58                   	pop    %rax
3c91     3c91:	fa                   	cli
3c92     3c92:	fb                   	sti
3c93     3c93:	9c                   	pushf
3c94     3c94:	58                   	pop    %rax
3c95     3c95:	fa                   	cli
3c96     3c96:	fb                   	sti
3c97     3c97:	9c                   	pushf
3c98     3c98:	58                   	pop    %rax
3c99     3c99:	fa                   	cli
3c9a     3c9a:	fb                   	sti
3c9b     3c9b:	9c                   	pushf
3c9c     3c9c:	58                   	pop    %rax
3c9d     3c9d:	fa                   	cli
3c9e     3c9e:	fb                   	sti
3c9f     3c9f:	9c                   	pushf
3ca0     3ca0:	58                   	pop    %rax
3ca1     3ca1:	fa                   	cli
3ca2     3ca2:	fb                   	sti
3ca3     3ca3:	9c                   	pushf
3ca4     3ca4:	58                   	pop    %rax
3ca5     3ca5:	fa                   	cli
3ca6     3ca6:	fb                   	sti
3ca7     3ca7:	9c                   	pushf
3ca8     3ca8:	58                   	pop    %rax
3ca9     3ca9:	fa                   	cli
3caa     3caa:	fb                   	sti
3cab     3cab:	9c                   	pushf
3cac     3cac:	58                   	pop    %rax
3cad     3cad:	fa                   	cli
3cae     3cae:	fb                   	sti
3caf     3caf:	9c                   	pushf
3cb0     3cb0:	58                   	pop    %rax
3cb1     3cb1:	fa                   	cli
3cb2     3cb2:	fb                   	sti
3cb3     3cb3:	9c                   	pushf
3cb4     3cb4:	58                   	pop    %rax
3cb5     3cb5:	fa                   	cli
3cb6     3cb6:	fb                   	sti
3cb7     3cb7:	9c                   	pushf
3cb8     3cb8:	58                   	pop    %rax
3cb9     3cb9:	fa                   	cli
3cba     3cba:	fb                   	sti
3cbb     3cbb:	9c                   	pushf
3cbc     3cbc:	58                   	pop    %rax
3cbd     3cbd:	fa                   	cli
3cbe     3cbe:	fb                   	sti
3cbf     3cbf:	9c                   	pushf
3cc0     3cc0:	58                   	pop    %rax
3cc1     3cc1:	fa                   	cli
3cc2     3cc2:	fb                   	sti
3cc3     3cc3:	9c                   	pushf
3cc4     3cc4:	58                   	pop    %rax
3cc5     3cc5:	fa                   	cli
3cc6     3cc6:	fb                   	sti
3cc7     3cc7:	9c                   	pushf
3cc8     3cc8:	58                   	pop    %rax
3cc9     3cc9:	fa                   	cli
3cca     3cca:	fb                   	sti
3ccb     3ccb:	9c                   	pushf
3ccc     3ccc:	58                   	pop    %rax
3ccd     3ccd:	fa                   	cli
3cce     3cce:	fb                   	sti
3ccf     3ccf:	9c                   	pushf
3cd0     3cd0:	58                   	pop    %rax
3cd1     3cd1:	fa                   	cli
3cd2     3cd2:	fb                   	sti
3cd3     3cd3:	9c                   	pushf
3cd4     3cd4:	58                   	pop    %rax
3cd5     3cd5:	fa                   	cli
3cd6     3cd6:	fb                   	sti
3cd7     3cd7:	9c                   	pushf
3cd8     3cd8:	58                   	pop    %rax
3cd9     3cd9:	fa                   	cli
3cda     3cda:	fb                   	sti
3cdb     3cdb:	9c                   	pushf
3cdc     3cdc:	58                   	pop    %rax
3cdd     3cdd:	fb                   	sti
3cde     3cde:	9c                   	pushf
3cdf     3cdf:	58                   	pop    %rax
3ce0     3ce0:	fa                   	cli
3ce1     3ce1:	9c                   	pushf
3ce2     3ce2:	58                   	pop    %rax
3ce3     3ce3:	fa                   	cli
3ce4     3ce4:	9c                   	pushf
3ce5     3ce5:	58                   	pop    %rax
3ce6     3ce6:	fa                   	cli
3ce7     3ce7:	fb                   	sti
3ce8     3ce8:	9c                   	pushf
3ce9     3ce9:	58                   	pop    %rax
3cea     3cea:	fa                   	cli
3ceb     3ceb:	9c                   	pushf
3cec     3cec:	58                   	pop    %rax
3ced     3ced:	fa                   	cli
3cee     3cee:	9c                   	pushf
3cef     3cef:	58                   	pop    %rax
3cf0     3cf0:	fa                   	cli
3cf1     3cf1:	9c                   	pushf
3cf2     3cf2:	58                   	pop    %rax
3cf3     3cf3:	fa                   	cli
3cf4     3cf4:	9c                   	pushf
3cf5     3cf5:	58                   	pop    %rax
3cf6     3cf6:	fa                   	cli
3cf7     3cf7:	9c                   	pushf
3cf8     3cf8:	58                   	pop    %rax
3cf9     3cf9:	fa                   	cli
3cfa     3cfa:	9c                   	pushf
3cfb     3cfb:	58                   	pop    %rax
3cfc     3cfc:	fa                   	cli
3cfd     3cfd:	9c                   	pushf
3cfe     3cfe:	58                   	pop    %rax
3cff     3cff:	fa                   	cli
3d00     3d00:	9c                   	pushf
3d01     3d01:	58                   	pop    %rax
3d02     3d02:	fa                   	cli
3d03     3d03:	9c                   	pushf
3d04     3d04:	58                   	pop    %rax
3d05     3d05:	fa                   	cli
3d06     3d06:	fb                   	sti
3d07     3d07:	9c                   	pushf
3d08     3d08:	58                   	pop    %rax
3d09     3d09:	fa                   	cli
3d0a     3d0a:	fb                   	sti
3d0b     3d0b:	9c                   	pushf
3d0c     3d0c:	58                   	pop    %rax
3d0d     3d0d:	fa                   	cli
3d0e     3d0e:	9c                   	pushf
3d0f     3d0f:	58                   	pop    %rax
3d10     3d10:	fa                   	cli
3d11     3d11:	9c                   	pushf
3d12     3d12:	58                   	pop    %rax
3d13     3d13:	fa                   	cli
3d14     3d14:	fb                   	sti
3d15     3d15:	9c                   	pushf
3d16     3d16:	58                   	pop    %rax
3d17     3d17:	fa                   	cli
3d18     3d18:	fb                   	sti
3d19     3d19:	9c                   	pushf
3d1a     3d1a:	58                   	pop    %rax
3d1b     3d1b:	fa                   	cli
3d1c     3d1c:	fb                   	sti
3d1d     3d1d:	9c                   	pushf
3d1e     3d1e:	58                   	pop    %rax
3d1f     3d1f:	fa                   	cli
3d20     3d20:	fb                   	sti
3d21     3d21:	9c                   	pushf
3d22     3d22:	58                   	pop    %rax
3d23     3d23:	9c                   	pushf
3d24     3d24:	58                   	pop    %rax
3d25     3d25:	fa                   	cli
3d26     3d26:	9c                   	pushf
3d27     3d27:	58                   	pop    %rax
3d28     3d28:	fb                   	sti
3d29     3d29:	9c                   	pushf
3d2a     3d2a:	58                   	pop    %rax
3d2b     3d2b:	fa                   	cli
3d2c     3d2c:	9c                   	pushf
3d2d     3d2d:	58                   	pop    %rax
3d2e     3d2e:	fb                   	sti
3d2f     3d2f:	9c                   	pushf
3d30     3d30:	58                   	pop    %rax
3d31     3d31:	9c                   	pushf
3d32     3d32:	58                   	pop    %rax
3d33     3d33:	fa                   	cli
3d34     3d34:	9c                   	pushf
3d35     3d35:	58                   	pop    %rax
3d36     3d36:	fb                   	sti
3d37     3d37:	9c                   	pushf
3d38     3d38:	58                   	pop    %rax
3d39     3d39:	fa                   	cli
3d3a     3d3a:	9c                   	pushf
3d3b     3d3b:	58                   	pop    %rax
3d3c     3d3c:	fb                   	sti
3d3d     3d3d:	9c                   	pushf
3d3e     3d3e:	58                   	pop    %rax
3d3f     3d3f:	fa                   	cli
3d40     3d40:	9c                   	pushf
3d41     3d41:	58                   	pop    %rax
3d42     3d42:	fb                   	sti
3d43     3d43:	48 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbp
3d4d     3d4d:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
3d57     3d57:	0f 01 cb             	stac
3d5a     3d5a:	0f ae e8             	lfence
3d5d     3d5d:	0f 01 ca             	clac
3d60     3d60:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
3d6a     3d6a:	49 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r13
3d74     3d74:	0f 01 cb             	stac
3d77     3d77:	0f ae e8             	lfence
3d7a     3d7a:	0f 01 ca             	clac
3d7d     3d7d:	9c                   	pushf
3d7e     3d7e:	58                   	pop    %rax
3d7f     3d7f:	fa                   	cli
3d80     3d80:	9c                   	pushf
3d81     3d81:	58                   	pop    %rax
3d82     3d82:	fb                   	sti
3d83     3d83:	9c                   	pushf
3d84     3d84:	58                   	pop    %rax
3d85     3d85:	fa                   	cli
3d86     3d86:	fb                   	sti
3d87     3d87:	9c                   	pushf
3d88     3d88:	58                   	pop    %rax
3d89     3d89:	fa                   	cli
3d8a     3d8a:	9c                   	pushf
3d8b     3d8b:	58                   	pop    %rax
3d8c     3d8c:	fb                   	sti
3d8d     3d8d:	9c                   	pushf
3d8e     3d8e:	58                   	pop    %rax
3d8f     3d8f:	fa                   	cli
3d90     3d90:	fb                   	sti
3d91     3d91:	9c                   	pushf
3d92     3d92:	58                   	pop    %rax
3d93     3d93:	fa                   	cli
3d94     3d94:	fb                   	sti
3d95     3d95:	9c                   	pushf
3d96     3d96:	5b                   	pop    %rbx
3d97     3d97:	0f 01 ca             	clac
3d9a     3d9a:	53                   	push   %rbx
3d9b     3d9b:	9d                   	popf
3d9c     3d9c:	9c                   	pushf
3d9d     3d9d:	41 5d                	pop    %r13
3d9f     3d9f:	0f 01 ca             	clac
3da2     3da2:	41 55                	push   %r13
3da4     3da4:	9d                   	popf
3da5     3da5:	0f 09                	wbinvd
3da7     3da7:	9c                   	pushf
3da8     3da8:	58                   	pop    %rax
3da9     3da9:	fa                   	cli
3daa     3daa:	9c                   	pushf
3dab     3dab:	58                   	pop    %rax
3dac     3dac:	fb                   	sti
3dad     3dad:	9c                   	pushf
3dae     3dae:	58                   	pop    %rax
3daf     3daf:	fb                   	sti
3db0     3db0:	9c                   	pushf
3db1     3db1:	58                   	pop    %rax
3db2     3db2:	fa                   	cli
3db3     3db3:	9c                   	pushf
3db4     3db4:	58                   	pop    %rax
3db5     3db5:	fb                   	sti
3db6     3db6:	9c                   	pushf
3db7     3db7:	58                   	pop    %rax
3db8     3db8:	fa                   	cli
3db9     3db9:	9c                   	pushf
3dba     3dba:	58                   	pop    %rax
3dbb     3dbb:	fb                   	sti
3dbc     3dbc:	9c                   	pushf
3dbd     3dbd:	58                   	pop    %rax
3dbe     3dbe:	fb                   	sti
3dbf     3dbf:	9c                   	pushf
3dc0     3dc0:	58                   	pop    %rax
3dc1     3dc1:	fa                   	cli
3dc2     3dc2:	9c                   	pushf
3dc3     3dc3:	58                   	pop    %rax
3dc4     3dc4:	fb                   	sti
3dc5     3dc5:	9c                   	pushf
3dc6     3dc6:	58                   	pop    %rax
3dc7     3dc7:	fa                   	cli
3dc8     3dc8:	9c                   	pushf
3dc9     3dc9:	58                   	pop    %rax
3dca     3dca:	fb                   	sti
3dcb     3dcb:	e9 00 00 00 00       	jmp    3dd0 <.altinstr_replacement+0x3dd0>	3dcc: R_X86_64_PC32	.text+0x27f09d2
3dd0     3dd0:	e9 00 00 00 00       	jmp    3dd5 <.altinstr_replacement+0x3dd5>	3dd1: R_X86_64_PC32	.text+0x27f0be8
3dd5     3dd5:	0f 01 cb             	stac
3dd8     3dd8:	0f 01 ca             	clac
3ddb     3ddb:	0f 01 cb             	stac
3dde     3dde:	0f 01 ca             	clac
3de1     3de1:	e8 00 00 00 00       	call   3de6 <.altinstr_replacement+0x3de6>	3de2: R_X86_64_PLT32	copy_user_generic_string-0x4
3de6     3de6:	e8 00 00 00 00       	call   3deb <.altinstr_replacement+0x3deb>	3de7: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
3deb     3deb:	0f 01 cb             	stac
3dee     3dee:	0f 01 cb             	stac
3df1     3df1:	0f 01 ca             	clac
3df4     3df4:	0f 01 cb             	stac
3df7     3df7:	0f 01 ca             	clac
3dfa     3dfa:	0f 01 ca             	clac
3dfd     3dfd:	0f 01 ca             	clac
3e00     3e00:	0f 01 ca             	clac
3e03     3e03:	0f 01 cb             	stac
3e06     3e06:	0f 01 ca             	clac
3e09     3e09:	0f ae e8             	lfence
3e0c     3e0c:	0f 31                	rdtsc
3e0e     3e0e:	0f 01 f9             	rdtscp
3e11     3e11:	0f ae e8             	lfence
3e14     3e14:	0f 31                	rdtsc
3e16     3e16:	0f 01 f9             	rdtscp
3e19     3e19:	0f ae e8             	lfence
3e1c     3e1c:	0f 31                	rdtsc
3e1e     3e1e:	0f 01 f9             	rdtscp
3e21     3e21:	0f ae e8             	lfence
3e24     3e24:	0f 31                	rdtsc
3e26     3e26:	0f 01 f9             	rdtscp
3e29     3e29:	48 ba 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rdx
3e33     3e33:	0f 01 cb             	stac
3e36     3e36:	0f 01 ca             	clac
3e39     3e39:	48 ba ff ef ff ff ff ff ff 00 	movabs $0xffffffffffefff,%rdx
3e43     3e43:	0f 01 cb             	stac
3e46     3e46:	0f 01 ca             	clac
3e49     3e49:	48 ba fd ef ff ff ff ff ff 00 	movabs $0xffffffffffeffd,%rdx
3e53     3e53:	0f 01 cb             	stac
3e56     3e56:	0f 01 ca             	clac
3e59     3e59:	48 ba f9 ef ff ff ff ff ff 00 	movabs $0xffffffffffeff9,%rdx
3e63     3e63:	0f 01 cb             	stac
3e66     3e66:	0f 01 ca             	clac
3e69     3e69:	0f 01 cb             	stac
3e6c     3e6c:	0f ae e8             	lfence
3e6f     3e6f:	0f 01 ca             	clac
3e72     3e72:	0f 01 cb             	stac
3e75     3e75:	0f ae e8             	lfence
3e78     3e78:	0f 01 ca             	clac
3e7b     3e7b:	0f 01 cb             	stac
3e7e     3e7e:	0f ae e8             	lfence
3e81     3e81:	0f 01 ca             	clac
3e84     3e84:	0f 01 cb             	stac
3e87     3e87:	0f ae e8             	lfence
3e8a     3e8a:	0f 01 ca             	clac
3e8d     3e8d:	0f 01 ca             	clac
3e90     3e90:	e8 00 00 00 00       	call   3e95 <.altinstr_replacement+0x3e95>	3e91: R_X86_64_PLT32	copy_user_generic_string-0x4
3e95     3e95:	e8 00 00 00 00       	call   3e9a <.altinstr_replacement+0x3e9a>	3e96: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
3e9a     3e9a:	e9 00 00 00 00       	jmp    3e9f <.altinstr_replacement+0x3e9f>	3e9b: R_X86_64_PC32	.noinstr.text+0xab8c
3e9f     3e9f:	e9 00 00 00 00       	jmp    3ea4 <.altinstr_replacement+0x3ea4>	3ea0: R_X86_64_PC32	.text+0x27f76c9
3ea4     3ea4:	e9 00 00 00 00       	jmp    3ea9 <.altinstr_replacement+0x3ea9>	3ea5: R_X86_64_PC32	.text+0x27f771c
3ea9     3ea9:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
3eb3     3eb3:	0f 01 cb             	stac
3eb6     3eb6:	0f 01 ca             	clac
3eb9     3eb9:	48 bb ff ef ff ff ff ff ff 00 	movabs $0xffffffffffefff,%rbx
3ec3     3ec3:	0f 01 cb             	stac
3ec6     3ec6:	0f 01 ca             	clac
3ec9     3ec9:	48 bb fd ef ff ff ff ff ff 00 	movabs $0xffffffffffeffd,%rbx
3ed3     3ed3:	0f 01 cb             	stac
3ed6     3ed6:	0f 01 ca             	clac
3ed9     3ed9:	48 bb f9 ef ff ff ff ff ff 00 	movabs $0xffffffffffeff9,%rbx
3ee3     3ee3:	0f 01 cb             	stac
3ee6     3ee6:	0f 01 ca             	clac
3ee9     3ee9:	0f 01 ca             	clac
3eec     3eec:	0f ae e8             	lfence
3eef     3eef:	ff e0                	jmp    *%rax
3ef1     3ef1:	cc                   	int3
3ef2     3ef2:	ff e0                	jmp    *%rax
3ef4     3ef4:	0f ae e8             	lfence
3ef7     3ef7:	ff e1                	jmp    *%rcx
3ef9     3ef9:	cc                   	int3
3efa     3efa:	ff e1                	jmp    *%rcx
3efc     3efc:	0f ae e8             	lfence
3eff     3eff:	ff e2                	jmp    *%rdx
3f01     3f01:	cc                   	int3
3f02     3f02:	ff e2                	jmp    *%rdx
3f04     3f04:	0f ae e8             	lfence
3f07     3f07:	ff e3                	jmp    *%rbx
3f09     3f09:	cc                   	int3
3f0a     3f0a:	ff e3                	jmp    *%rbx
3f0c     3f0c:	0f ae e8             	lfence
3f0f     3f0f:	ff e4                	jmp    *%rsp
3f11     3f11:	cc                   	int3
3f12     3f12:	ff e4                	jmp    *%rsp
3f14     3f14:	0f ae e8             	lfence
3f17     3f17:	ff e5                	jmp    *%rbp
3f19     3f19:	cc                   	int3
3f1a     3f1a:	ff e5                	jmp    *%rbp
3f1c     3f1c:	0f ae e8             	lfence
3f1f     3f1f:	ff e6                	jmp    *%rsi
3f21     3f21:	cc                   	int3
3f22     3f22:	ff e6                	jmp    *%rsi
3f24     3f24:	0f ae e8             	lfence
3f27     3f27:	ff e7                	jmp    *%rdi
3f29     3f29:	cc                   	int3
3f2a     3f2a:	ff e7                	jmp    *%rdi
3f2c     3f2c:	0f ae e8             	lfence
3f2f     3f2f:	41 ff e0             	jmp    *%r8
3f32     3f32:	cc                   	int3
3f33     3f33:	41 ff e0             	jmp    *%r8
3f36     3f36:	0f ae e8             	lfence
3f39     3f39:	41 ff e1             	jmp    *%r9
3f3c     3f3c:	cc                   	int3
3f3d     3f3d:	41 ff e1             	jmp    *%r9
3f40     3f40:	0f ae e8             	lfence
3f43     3f43:	41 ff e2             	jmp    *%r10
3f46     3f46:	cc                   	int3
3f47     3f47:	41 ff e2             	jmp    *%r10
3f4a     3f4a:	0f ae e8             	lfence
3f4d     3f4d:	41 ff e3             	jmp    *%r11
3f50     3f50:	cc                   	int3
3f51     3f51:	41 ff e3             	jmp    *%r11
3f54     3f54:	0f ae e8             	lfence
3f57     3f57:	41 ff e4             	jmp    *%r12
3f5a     3f5a:	cc                   	int3
3f5b     3f5b:	41 ff e4             	jmp    *%r12
3f5e     3f5e:	0f ae e8             	lfence
3f61     3f61:	41 ff e5             	jmp    *%r13
3f64     3f64:	cc                   	int3
3f65     3f65:	41 ff e5             	jmp    *%r13
3f68     3f68:	0f ae e8             	lfence
3f6b     3f6b:	41 ff e6             	jmp    *%r14
3f6e     3f6e:	cc                   	int3
3f6f     3f6f:	41 ff e6             	jmp    *%r14
3f72     3f72:	0f ae e8             	lfence
3f75     3f75:	41 ff e7             	jmp    *%r15
3f78     3f78:	cc                   	int3
3f79     3f79:	41 ff e7             	jmp    *%r15
3f7c     3f7c:	48 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbp
3f86     3f86:	e8 00 00 00 00       	call   3f8b <.altinstr_replacement+0x3f8b>	3f87: R_X86_64_PLT32	copy_user_generic_string-0x4
3f8b     3f8b:	e8 00 00 00 00       	call   3f90 <.altinstr_replacement+0x3f90>	3f8c: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
3f90     3f90:	66 0f ae 38          	clflushopt (%rax)
3f94     3f94:	66 0f ae 30          	clwb   (%rax)
3f98     3f98:	0f 01 cb             	stac
3f9b     3f9b:	0f 01 ca             	clac
3f9e     3f9e:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
3fa8     3fa8:	f3 0f b8 c7          	popcnt %edi,%eax
3fac     3fac:	f3 48 0f b8 c7       	popcnt %rdi,%rax
3fb1     3fb1:	f3 48 0f b8 c7       	popcnt %rdi,%rax
3fb6     3fb6:	f3 48 0f b8 c7       	popcnt %rdi,%rax
3fbb     3fbb:	f3 48 0f b8 c7       	popcnt %rdi,%rax
3fc0     3fc0:	f3 48 0f b8 c7       	popcnt %rdi,%rax
3fc5     3fc5:	48 ba 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rdx
3fcf     3fcf:	49 bf 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r15
3fd9     3fd9:	e8 00 00 00 00       	call   3fde <.altinstr_replacement+0x3fde>	3fda: R_X86_64_PLT32	__x86_indirect_thunk_r12-0x4
3fde     3fde:	0f ae e8             	lfence
3fe1     3fe1:	41 ff d4             	call   *%r12
3fe4     3fe4:	9c                   	pushf
3fe5     3fe5:	58                   	pop    %rax
3fe6     3fe6:	fa                   	cli
3fe7     3fe7:	fb                   	sti
3fe8     3fe8:	e9 00 00 00 00       	jmp    3fed <.altinstr_replacement+0x3fed>	3fe9: R_X86_64_PC32	.init.text+0x19aa13
3fed     3fed:	e9 00 00 00 00       	jmp    3ff2 <.altinstr_replacement+0x3ff2>	3fee: R_X86_64_PC32	.text+0x2bbdd42
3ff2     3ff2:	e9 00 00 00 00       	jmp    3ff7 <.altinstr_replacement+0x3ff7>	3ff3: R_X86_64_PC32	.text+0x2bbdc6e
3ff7     3ff7:	fb                   	sti
3ff8     3ff8:	9c                   	pushf
3ff9     3ff9:	58                   	pop    %rax
3ffa     3ffa:	fa                   	cli
3ffb     3ffb:	9c                   	pushf
3ffc     3ffc:	58                   	pop    %rax
3ffd     3ffd:	9c                   	pushf
3ffe     3ffe:	58                   	pop    %rax
3fff     3fff:	9c                   	pushf
4000     4000:	58                   	pop    %rax
4001     4001:	fa                   	cli
4002     4002:	9c                   	pushf
4003     4003:	58                   	pop    %rax
4004     4004:	9c                   	pushf
4005     4005:	58                   	pop    %rax
4006     4006:	0f 30                	wrmsr
4008     4008:	0f 30                	wrmsr
400a     400a:	0f 30                	wrmsr
400c     400c:	9c                   	pushf
400d     400d:	58                   	pop    %rax
400e     400e:	9c                   	pushf
400f     400f:	58                   	pop    %rax
4010     4010:	9c                   	pushf
4011     4011:	58                   	pop    %rax
4012     4012:	9c                   	pushf
4013     4013:	58                   	pop    %rax
4014     4014:	9c                   	pushf
4015     4015:	58                   	pop    %rax
4016     4016:	9c                   	pushf
4017     4017:	58                   	pop    %rax
4018     4018:	9c                   	pushf
4019     4019:	58                   	pop    %rax
401a     401a:	9c                   	pushf
401b     401b:	58                   	pop    %rax
401c     401c:	9c                   	pushf
401d     401d:	58                   	pop    %rax
401e     401e:	9c                   	pushf
401f     401f:	58                   	pop    %rax
4020     4020:	9c                   	pushf
4021     4021:	58                   	pop    %rax
4022     4022:	9c                   	pushf
4023     4023:	58                   	pop    %rax
4024     4024:	9c                   	pushf
4025     4025:	58                   	pop    %rax
4026     4026:	9c                   	pushf
4027     4027:	58                   	pop    %rax
4028     4028:	9c                   	pushf
4029     4029:	58                   	pop    %rax
402a     402a:	e9 00 00 00 00       	jmp    402f <.altinstr_replacement+0x402f>	402b: R_X86_64_PC32	.text+0x2c5f0eb
402f     402f:	0f 09                	wbinvd
4031     4031:	9c                   	pushf
4032     4032:	58                   	pop    %rax
4033     4033:	9c                   	pushf
4034     4034:	58                   	pop    %rax
4035     4035:	9c                   	pushf
4036     4036:	58                   	pop    %rax
4037     4037:	9c                   	pushf
4038     4038:	58                   	pop    %rax
4039     4039:	9c                   	pushf
403a     403a:	58                   	pop    %rax
403b     403b:	9c                   	pushf
403c     403c:	58                   	pop    %rax
403d     403d:	9c                   	pushf
403e     403e:	58                   	pop    %rax
403f     403f:	9c                   	pushf
4040     4040:	58                   	pop    %rax
4041     4041:	9c                   	pushf
4042     4042:	58                   	pop    %rax
4043     4043:	9c                   	pushf
4044     4044:	58                   	pop    %rax
4045     4045:	9c                   	pushf
4046     4046:	58                   	pop    %rax
4047     4047:	9c                   	pushf
4048     4048:	58                   	pop    %rax
4049     4049:	9c                   	pushf
404a     404a:	58                   	pop    %rax
404b     404b:	9c                   	pushf
404c     404c:	58                   	pop    %rax
404d     404d:	9c                   	pushf
404e     404e:	58                   	pop    %rax
404f     404f:	9c                   	pushf
4050     4050:	58                   	pop    %rax
4051     4051:	9c                   	pushf
4052     4052:	58                   	pop    %rax
4053     4053:	9c                   	pushf
4054     4054:	58                   	pop    %rax
4055     4055:	9c                   	pushf
4056     4056:	58                   	pop    %rax
4057     4057:	9c                   	pushf
4058     4058:	58                   	pop    %rax
4059     4059:	9c                   	pushf
405a     405a:	58                   	pop    %rax
405b     405b:	9c                   	pushf
405c     405c:	58                   	pop    %rax
405d     405d:	9c                   	pushf
405e     405e:	58                   	pop    %rax
405f     405f:	9c                   	pushf
4060     4060:	58                   	pop    %rax
4061     4061:	9c                   	pushf
4062     4062:	58                   	pop    %rax
4063     4063:	9c                   	pushf
4064     4064:	58                   	pop    %rax
4065     4065:	9c                   	pushf
4066     4066:	58                   	pop    %rax
4067     4067:	9c                   	pushf
4068     4068:	58                   	pop    %rax
4069     4069:	9c                   	pushf
406a     406a:	58                   	pop    %rax
406b     406b:	9c                   	pushf
406c     406c:	58                   	pop    %rax
406d     406d:	9c                   	pushf
406e     406e:	58                   	pop    %rax
406f     406f:	9c                   	pushf
4070     4070:	58                   	pop    %rax
4071     4071:	9c                   	pushf
4072     4072:	58                   	pop    %rax
4073     4073:	9c                   	pushf
4074     4074:	58                   	pop    %rax
4075     4075:	9c                   	pushf
4076     4076:	58                   	pop    %rax
4077     4077:	fa                   	cli
4078     4078:	e9 00 00 00 00       	jmp    407d <.altinstr_replacement+0x407d>	4079: R_X86_64_PC32	.cpuidle.text+0x128d
407d     407d:	0f 09                	wbinvd
407f     407f:	e9 00 00 00 00       	jmp    4084 <.altinstr_replacement+0x4084>	4080: R_X86_64_PC32	.text+0x2cb1d62
4084     4084:	0f 09                	wbinvd
4086     4086:	e9 00 00 00 00       	jmp    408b <.altinstr_replacement+0x408b>	4087: R_X86_64_PC32	.cpuidle.text+0x145a
408b     408b:	0f 09                	wbinvd
408d     408d:	9c                   	pushf
408e     408e:	58                   	pop    %rax
408f     408f:	fa                   	cli
4090     4090:	fb                   	sti
4091     4091:	9c                   	pushf
4092     4092:	58                   	pop    %rax
4093     4093:	fa                   	cli
4094     4094:	fb                   	sti
4095     4095:	9c                   	pushf
4096     4096:	58                   	pop    %rax
4097     4097:	9c                   	pushf
4098     4098:	58                   	pop    %rax
4099     4099:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
40a3     40a3:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
40ad     40ad:	e9 00 00 00 00       	jmp    40b2 <.altinstr_replacement+0x40b2>	40ae: R_X86_64_PC32	.text+0x2ce5082
40b2     40b2:	e9 00 00 00 00       	jmp    40b7 <.altinstr_replacement+0x40b7>	40b3: R_X86_64_PC32	.text+0x2ce4fae
40b7     40b7:	9c                   	pushf
40b8     40b8:	58                   	pop    %rax
40b9     40b9:	fa                   	cli
40ba     40ba:	fb                   	sti
40bb     40bb:	9c                   	pushf
40bc     40bc:	58                   	pop    %rax
40bd     40bd:	fa                   	cli
40be     40be:	9c                   	pushf
40bf     40bf:	58                   	pop    %rax
40c0     40c0:	9c                   	pushf
40c1     40c1:	58                   	pop    %rax
40c2     40c2:	fa                   	cli
40c3     40c3:	9c                   	pushf
40c4     40c4:	58                   	pop    %rax
40c5     40c5:	fb                   	sti
40c6     40c6:	e9 00 00 00 00       	jmp    40cb <.altinstr_replacement+0x40cb>	40c7: R_X86_64_PC32	.text+0x2cec3a2
40cb     40cb:	e9 00 00 00 00       	jmp    40d0 <.altinstr_replacement+0x40d0>	40cc: R_X86_64_PC32	.text+0x2cec3c5
40d0     40d0:	9c                   	pushf
40d1     40d1:	58                   	pop    %rax
40d2     40d2:	fa                   	cli
40d3     40d3:	9c                   	pushf
40d4     40d4:	58                   	pop    %rax
40d5     40d5:	fb                   	sti
40d6     40d6:	e9 00 00 00 00       	jmp    40db <.altinstr_replacement+0x40db>	40d7: R_X86_64_PC32	.init.text+0x1b952a
40db     40db:	e9 00 00 00 00       	jmp    40e0 <.altinstr_replacement+0x40e0>	40dc: R_X86_64_PC32	.init.text+0x1b954a
40e0     40e0:	f3 0f b8 c7          	popcnt %edi,%eax
40e4     40e4:	e8 00 00 00 00       	call   40e9 <.altinstr_replacement+0x40e9>	40e5: R_X86_64_PLT32	clear_page_rep-0x4
40e9     40e9:	e8 00 00 00 00       	call   40ee <.altinstr_replacement+0x40ee>	40ea: R_X86_64_PLT32	clear_page_erms-0x4
40ee     40ee:	9c                   	pushf
40ef     40ef:	58                   	pop    %rax
40f0     40f0:	e8 00 00 00 00       	call   40f5 <.altinstr_replacement+0x40f5>	40f1: R_X86_64_PLT32	clear_page_rep-0x4
40f5     40f5:	e8 00 00 00 00       	call   40fa <.altinstr_replacement+0x40fa>	40f6: R_X86_64_PLT32	clear_page_erms-0x4
40fa     40fa:	9c                   	pushf
40fb     40fb:	58                   	pop    %rax
40fc     40fc:	9c                   	pushf
40fd     40fd:	58                   	pop    %rax
40fe     40fe:	9c                   	pushf
40ff     40ff:	58                   	pop    %rax
4100     4100:	9c                   	pushf
4101     4101:	58                   	pop    %rax
4102     4102:	9c                   	pushf
4103     4103:	58                   	pop    %rax
4104     4104:	e8 00 00 00 00       	call   4109 <.altinstr_replacement+0x4109>	4105: R_X86_64_PLT32	clear_page_rep-0x4
4109     4109:	e8 00 00 00 00       	call   410e <.altinstr_replacement+0x410e>	410a: R_X86_64_PLT32	clear_page_erms-0x4
410e     410e:	e9 00 00 00 00       	jmp    4113 <.altinstr_replacement+0x4113>	410f: R_X86_64_PC32	.text+0x2e46948
4113     4113:	e9 00 00 00 00       	jmp    4118 <.altinstr_replacement+0x4118>	4114: R_X86_64_PC32	.text+0x2e4699b
4118     4118:	e9 00 00 00 00       	jmp    411d <.altinstr_replacement+0x411d>	4119: R_X86_64_PC32	.text+0x2e4c191
411d     411d:	e9 00 00 00 00       	jmp    4122 <.altinstr_replacement+0x4122>	411e: R_X86_64_PC32	.text+0x2e4c35d
4122     4122:	0f 01 cb             	stac
4125     4125:	e8 00 00 00 00       	call   412a <.altinstr_replacement+0x412a>	4126: R_X86_64_PLT32	__x86_indirect_thunk_rax-0x4
412a     412a:	0f ae e8             	lfence
412d     412d:	ff d0                	call   *%rax
412f     412f:	0f 01 ca             	clac
4132     4132:	48 ba 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rdx
413c     413c:	49 be 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r14
4146     4146:	0f 01 cb             	stac
4149     4149:	0f 01 ca             	clac
414c     414c:	48 89 f8             	mov    %rdi,%rax
414f     414f:	f3 0f b8 c7          	popcnt %edi,%eax
4153     4153:	f3 0f b8 c7          	popcnt %edi,%eax
4157     4157:	fb                   	sti
4158     4158:	9c                   	pushf
4159     4159:	58                   	pop    %rax
415a     415a:	fa                   	cli
415b     415b:	9c                   	pushf
415c     415c:	58                   	pop    %rax
415d     415d:	fb                   	sti
415e     415e:	f3 0f b8 c7          	popcnt %edi,%eax
4162     4162:	9c                   	pushf
4163     4163:	58                   	pop    %rax
4164     4164:	fa                   	cli
4165     4165:	9c                   	pushf
4166     4166:	58                   	pop    %rax
4167     4167:	fb                   	sti
4168     4168:	9c                   	pushf
4169     4169:	58                   	pop    %rax
416a     416a:	fa                   	cli
416b     416b:	9c                   	pushf
416c     416c:	58                   	pop    %rax
416d     416d:	fb                   	sti
416e     416e:	9c                   	pushf
416f     416f:	58                   	pop    %rax
4170     4170:	fa                   	cli
4171     4171:	9c                   	pushf
4172     4172:	58                   	pop    %rax
4173     4173:	fb                   	sti
4174     4174:	9c                   	pushf
4175     4175:	58                   	pop    %rax
4176     4176:	fa                   	cli
4177     4177:	9c                   	pushf
4178     4178:	58                   	pop    %rax
4179     4179:	fb                   	sti
417a     417a:	9c                   	pushf
417b     417b:	58                   	pop    %rax
417c     417c:	fa                   	cli
417d     417d:	9c                   	pushf
417e     417e:	58                   	pop    %rax
417f     417f:	fb                   	sti
4180     4180:	9c                   	pushf
4181     4181:	58                   	pop    %rax
4182     4182:	fa                   	cli
4183     4183:	9c                   	pushf
4184     4184:	58                   	pop    %rax
4185     4185:	fb                   	sti
4186     4186:	9c                   	pushf
4187     4187:	58                   	pop    %rax
4188     4188:	fa                   	cli
4189     4189:	9c                   	pushf
418a     418a:	58                   	pop    %rax
418b     418b:	fb                   	sti
418c     418c:	9c                   	pushf
418d     418d:	58                   	pop    %rax
418e     418e:	fa                   	cli
418f     418f:	9c                   	pushf
4190     4190:	58                   	pop    %rax
4191     4191:	fb                   	sti
4192     4192:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
419c     419c:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
41a6     41a6:	e9 00 00 00 00       	jmp    41ab <.altinstr_replacement+0x41ab>	41a7: R_X86_64_PC32	.text+0x30188c6
41ab     41ab:	e9 00 00 00 00       	jmp    41b0 <.altinstr_replacement+0x41b0>	41ac: R_X86_64_PC32	.text+0x3018932
41b0     41b0:	e9 00 00 00 00       	jmp    41b5 <.altinstr_replacement+0x41b5>	41b1: R_X86_64_PC32	.text+0x3019c00
41b5     41b5:	e9 00 00 00 00       	jmp    41ba <.altinstr_replacement+0x41ba>	41b6: R_X86_64_PC32	.text+0x3019c56
41ba     41ba:	9c                   	pushf
41bb     41bb:	58                   	pop    %rax
41bc     41bc:	fa                   	cli
41bd     41bd:	9c                   	pushf
41be     41be:	58                   	pop    %rax
41bf     41bf:	fb                   	sti
41c0     41c0:	9c                   	pushf
41c1     41c1:	58                   	pop    %rax
41c2     41c2:	fa                   	cli
41c3     41c3:	fb                   	sti
41c4     41c4:	fb                   	sti
41c5     41c5:	9c                   	pushf
41c6     41c6:	58                   	pop    %rax
41c7     41c7:	fa                   	cli
41c8     41c8:	9c                   	pushf
41c9     41c9:	58                   	pop    %rax
41ca     41ca:	fb                   	sti
41cb     41cb:	9c                   	pushf
41cc     41cc:	58                   	pop    %rax
41cd     41cd:	fa                   	cli
41ce     41ce:	9c                   	pushf
41cf     41cf:	58                   	pop    %rax
41d0     41d0:	fb                   	sti
41d1     41d1:	9c                   	pushf
41d2     41d2:	58                   	pop    %rax
41d3     41d3:	fa                   	cli
41d4     41d4:	9c                   	pushf
41d5     41d5:	58                   	pop    %rax
41d6     41d6:	fb                   	sti
41d7     41d7:	9c                   	pushf
41d8     41d8:	58                   	pop    %rax
41d9     41d9:	fa                   	cli
41da     41da:	9c                   	pushf
41db     41db:	58                   	pop    %rax
41dc     41dc:	fb                   	sti
41dd     41dd:	9c                   	pushf
41de     41de:	58                   	pop    %rax
41df     41df:	fa                   	cli
41e0     41e0:	0f 09                	wbinvd
41e2     41e2:	f3 0f b8 c7          	popcnt %edi,%eax
41e6     41e6:	e9 00 00 00 00       	jmp    41eb <.altinstr_replacement+0x41eb>	41e7: R_X86_64_PC32	.text+0x30d2f29
41eb     41eb:	e9 00 00 00 00       	jmp    41f0 <.altinstr_replacement+0x41f0>	41ec: R_X86_64_PC32	.text+0x30d4028
41f0     41f0:	e9 00 00 00 00       	jmp    41f5 <.altinstr_replacement+0x41f5>	41f1: R_X86_64_PC32	.text+0x30d4a21
41f5     41f5:	e9 00 00 00 00       	jmp    41fa <.altinstr_replacement+0x41fa>	41f6: R_X86_64_PC32	.text+0x30d4a5a
41fa     41fa:	e9 00 00 00 00       	jmp    41ff <.altinstr_replacement+0x41ff>	41fb: R_X86_64_PC32	.text+0x30f7bb2
41ff     41ff:	66 0f ae 3b          	clflushopt (%rbx)
4203     4203:	66 0f ae 7d ff       	clflushopt -0x1(%rbp)
4208     4208:	66 0f ae 38          	clflushopt (%rax)
420c     420c:	e9 00 00 00 00       	jmp    4211 <.altinstr_replacement+0x4211>	420d: R_X86_64_PC32	.text+0x30f8531
4211     4211:	e9 00 00 00 00       	jmp    4216 <.altinstr_replacement+0x4216>	4212: R_X86_64_PC32	.text+0x30f8696
4216     4216:	e9 00 00 00 00       	jmp    421b <.altinstr_replacement+0x421b>	4217: R_X86_64_PC32	.text+0x30f877c
421b     421b:	49 be 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r14
4225     4225:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
422f     422f:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
4239     4239:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
4243     4243:	f3 0f b8 c7          	popcnt %edi,%eax
4247     4247:	f3 0f b8 c7          	popcnt %edi,%eax
424b     424b:	f3 0f b8 c7          	popcnt %edi,%eax
424f     424f:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4254     4254:	f3 0f b8 c7          	popcnt %edi,%eax
4258     4258:	9c                   	pushf
4259     4259:	58                   	pop    %rax
425a     425a:	fa                   	cli
425b     425b:	9c                   	pushf
425c     425c:	58                   	pop    %rax
425d     425d:	fb                   	sti
425e     425e:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4263     4263:	f3 0f b8 c7          	popcnt %edi,%eax
4267     4267:	9c                   	pushf
4268     4268:	58                   	pop    %rax
4269     4269:	9c                   	pushf
426a     426a:	58                   	pop    %rax
426b     426b:	9c                   	pushf
426c     426c:	58                   	pop    %rax
426d     426d:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4272     4272:	f3 0f b8 c7          	popcnt %edi,%eax
4276     4276:	e8 00 00 00 00       	call   427b <.altinstr_replacement+0x427b>	4277: R_X86_64_PLT32	clear_page_rep-0x4
427b     427b:	e8 00 00 00 00       	call   4280 <.altinstr_replacement+0x4280>	427c: R_X86_64_PLT32	clear_page_erms-0x4
4280     4280:	0f 09                	wbinvd
4282     4282:	9c                   	pushf
4283     4283:	58                   	pop    %rax
4284     4284:	9c                   	pushf
4285     4285:	58                   	pop    %rax
4286     4286:	9c                   	pushf
4287     4287:	58                   	pop    %rax
4288     4288:	9c                   	pushf
4289     4289:	58                   	pop    %rax
428a     428a:	f3 0f b8 c7          	popcnt %edi,%eax
428e     428e:	f3 0f b8 c7          	popcnt %edi,%eax
4292     4292:	f3 0f b8 c7          	popcnt %edi,%eax
4296     4296:	f3 0f b8 c7          	popcnt %edi,%eax
429a     429a:	f3 0f b8 c7          	popcnt %edi,%eax
429e     429e:	f3 0f b8 c7          	popcnt %edi,%eax
42a2     42a2:	f3 0f b8 c7          	popcnt %edi,%eax
42a6     42a6:	f3 0f b8 c7          	popcnt %edi,%eax
42aa     42aa:	9c                   	pushf
42ab     42ab:	58                   	pop    %rax
42ac     42ac:	9c                   	pushf
42ad     42ad:	58                   	pop    %rax
42ae     42ae:	e9 00 00 00 00       	jmp    42b3 <.altinstr_replacement+0x42b3>	42af: R_X86_64_PC32	.text+0x34692ad
42b3     42b3:	e9 00 00 00 00       	jmp    42b8 <.altinstr_replacement+0x42b8>	42b4: R_X86_64_PC32	.text+0x3469308
42b8     42b8:	e9 00 00 00 00       	jmp    42bd <.altinstr_replacement+0x42bd>	42b9: R_X86_64_PC32	.text+0x34696f0
42bd     42bd:	e9 00 00 00 00       	jmp    42c2 <.altinstr_replacement+0x42c2>	42be: R_X86_64_PC32	.text+0x346974b
42c2     42c2:	f3 0f b8 c7          	popcnt %edi,%eax
42c6     42c6:	f3 0f b8 c7          	popcnt %edi,%eax
42ca     42ca:	f3 0f b8 c7          	popcnt %edi,%eax
42ce     42ce:	f3 0f b8 c7          	popcnt %edi,%eax
42d2     42d2:	f3 0f b8 c7          	popcnt %edi,%eax
42d6     42d6:	f3 0f b8 c7          	popcnt %edi,%eax
42da     42da:	f3 0f b8 c7          	popcnt %edi,%eax
42de     42de:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
42e8     42e8:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
42f2     42f2:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
42fc     42fc:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
4306     4306:	48 ba 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rdx
4310     4310:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
431a     431a:	f3 0f b8 c7          	popcnt %edi,%eax
431e     431e:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
4328     4328:	9c                   	pushf
4329     4329:	58                   	pop    %rax
432a     432a:	fa                   	cli
432b     432b:	9c                   	pushf
432c     432c:	58                   	pop    %rax
432d     432d:	fb                   	sti
432e     432e:	9c                   	pushf
432f     432f:	58                   	pop    %rax
4330     4330:	fa                   	cli
4331     4331:	9c                   	pushf
4332     4332:	58                   	pop    %rax
4333     4333:	fb                   	sti
4334     4334:	f3 0f b8 c7          	popcnt %edi,%eax
4338     4338:	f3 0f b8 c7          	popcnt %edi,%eax
433c     433c:	f3 0f b8 c7          	popcnt %edi,%eax
4340     4340:	f3 0f b8 c7          	popcnt %edi,%eax
4344     4344:	f3 0f b8 c7          	popcnt %edi,%eax
4348     4348:	f3 0f b8 c7          	popcnt %edi,%eax
434c     434c:	f3 0f b8 c7          	popcnt %edi,%eax
4350     4350:	f3 0f b8 c7          	popcnt %edi,%eax
4354     4354:	f3 0f b8 c7          	popcnt %edi,%eax
4358     4358:	f3 0f b8 c7          	popcnt %edi,%eax
435c     435c:	e9 00 00 00 00       	jmp    4361 <.altinstr_replacement+0x4361>	435d: R_X86_64_PC32	.text+0x3df707c
4361     4361:	48 89 f8             	mov    %rdi,%rax
4364     4364:	f3 0f b8 c7          	popcnt %edi,%eax
4368     4368:	f3 0f b8 c7          	popcnt %edi,%eax
436c     436c:	f3 0f b8 c7          	popcnt %edi,%eax
4370     4370:	f3 0f b8 c7          	popcnt %edi,%eax
4374     4374:	f3 0f b8 c7          	popcnt %edi,%eax
4378     4378:	f3 0f b8 c7          	popcnt %edi,%eax
437c     437c:	9c                   	pushf
437d     437d:	58                   	pop    %rax
437e     437e:	fa                   	cli
437f     437f:	fb                   	sti
4380     4380:	f3 0f b8 c7          	popcnt %edi,%eax
4384     4384:	9c                   	pushf
4385     4385:	58                   	pop    %rax
4386     4386:	9c                   	pushf
4387     4387:	58                   	pop    %rax
4388     4388:	fa                   	cli
4389     4389:	fb                   	sti
438a     438a:	9c                   	pushf
438b     438b:	58                   	pop    %rax
438c     438c:	fa                   	cli
438d     438d:	9c                   	pushf
438e     438e:	58                   	pop    %rax
438f     438f:	fb                   	sti
4390     4390:	9c                   	pushf
4391     4391:	58                   	pop    %rax
4392     4392:	fa                   	cli
4393     4393:	9c                   	pushf
4394     4394:	58                   	pop    %rax
4395     4395:	fb                   	sti
4396     4396:	9c                   	pushf
4397     4397:	58                   	pop    %rax
4398     4398:	fa                   	cli
4399     4399:	9c                   	pushf
439a     439a:	58                   	pop    %rax
439b     439b:	fb                   	sti
439c     439c:	9c                   	pushf
439d     439d:	58                   	pop    %rax
439e     439e:	fa                   	cli
439f     439f:	fb                   	sti
43a0     43a0:	9c                   	pushf
43a1     43a1:	58                   	pop    %rax
43a2     43a2:	fa                   	cli
43a3     43a3:	fb                   	sti
43a4     43a4:	9c                   	pushf
43a5     43a5:	58                   	pop    %rax
43a6     43a6:	fa                   	cli
43a7     43a7:	9c                   	pushf
43a8     43a8:	58                   	pop    %rax
43a9     43a9:	fb                   	sti
43aa     43aa:	9c                   	pushf
43ab     43ab:	58                   	pop    %rax
43ac     43ac:	fa                   	cli
43ad     43ad:	fb                   	sti
43ae     43ae:	9c                   	pushf
43af     43af:	58                   	pop    %rax
43b0     43b0:	fa                   	cli
43b1     43b1:	fb                   	sti
43b2     43b2:	9c                   	pushf
43b3     43b3:	58                   	pop    %rax
43b4     43b4:	fa                   	cli
43b5     43b5:	fb                   	sti
43b6     43b6:	f3 0f b8 c7          	popcnt %edi,%eax
43ba     43ba:	f3 0f b8 c7          	popcnt %edi,%eax
43be     43be:	f3 0f b8 c7          	popcnt %edi,%eax
43c2     43c2:	f3 0f b8 c7          	popcnt %edi,%eax
43c6     43c6:	f3 0f b8 c7          	popcnt %edi,%eax
43ca     43ca:	f3 0f b8 c7          	popcnt %edi,%eax
43ce     43ce:	f3 0f b8 c7          	popcnt %edi,%eax
43d2     43d2:	f3 0f b8 c7          	popcnt %edi,%eax
43d6     43d6:	f3 0f b8 c7          	popcnt %edi,%eax
43da     43da:	f3 48 0f b8 c7       	popcnt %rdi,%rax
43df     43df:	f3 0f b8 c7          	popcnt %edi,%eax
43e3     43e3:	f3 0f b8 c7          	popcnt %edi,%eax
43e7     43e7:	f3 0f b8 c7          	popcnt %edi,%eax
43eb     43eb:	f3 0f b8 c7          	popcnt %edi,%eax
43ef     43ef:	f3 0f b8 c7          	popcnt %edi,%eax
43f3     43f3:	f3 0f b8 c7          	popcnt %edi,%eax
43f7     43f7:	f3 0f b8 c7          	popcnt %edi,%eax
43fb     43fb:	f3 0f b8 c7          	popcnt %edi,%eax
43ff     43ff:	f3 0f b8 c7          	popcnt %edi,%eax
4403     4403:	f3 0f b8 c7          	popcnt %edi,%eax
4407     4407:	f3 0f b8 c7          	popcnt %edi,%eax
440b     440b:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4410     4410:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4415     4415:	f3 0f b8 c7          	popcnt %edi,%eax
4419     4419:	f3 0f b8 c7          	popcnt %edi,%eax
441d     441d:	f3 0f b8 c7          	popcnt %edi,%eax
4421     4421:	f3 0f b8 c7          	popcnt %edi,%eax
4425     4425:	f3 0f b8 c7          	popcnt %edi,%eax
4429     4429:	f3 0f b8 c7          	popcnt %edi,%eax
442d     442d:	f3 0f b8 c7          	popcnt %edi,%eax
4431     4431:	f3 0f b8 c7          	popcnt %edi,%eax
4435     4435:	f3 0f b8 c7          	popcnt %edi,%eax
4439     4439:	f3 0f b8 c7          	popcnt %edi,%eax
443d     443d:	f3 0f b8 c7          	popcnt %edi,%eax
4441     4441:	f3 0f b8 c7          	popcnt %edi,%eax
4445     4445:	f3 0f b8 c7          	popcnt %edi,%eax
4449     4449:	e9 00 00 00 00       	jmp    444e <.altinstr_replacement+0x444e>	444a: R_X86_64_PC32	.text+0x3f04efc
444e     444e:	e9 00 00 00 00       	jmp    4453 <.altinstr_replacement+0x4453>	444f: R_X86_64_PC32	.text+0x3f05272
4453     4453:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
445d     445d:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4462     4462:	e8 00 00 00 00       	call   4467 <.altinstr_replacement+0x4467>	4463: R_X86_64_PLT32	copy_user_generic_string-0x4
4467     4467:	e8 00 00 00 00       	call   446c <.altinstr_replacement+0x446c>	4468: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
446c     446c:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
4476     4476:	0f 01 cb             	stac
4479     4479:	0f ae e8             	lfence
447c     447c:	0f 01 ca             	clac
447f     447f:	0f 01 ca             	clac
4482     4482:	48 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbp
448c     448c:	e8 00 00 00 00       	call   4491 <.altinstr_replacement+0x4491>	448d: R_X86_64_PLT32	copy_user_generic_string-0x4
4491     4491:	e8 00 00 00 00       	call   4496 <.altinstr_replacement+0x4496>	4492: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
4496     4496:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
44a0     44a0:	e8 00 00 00 00       	call   44a5 <.altinstr_replacement+0x44a5>	44a1: R_X86_64_PLT32	copy_user_generic_string-0x4
44a5     44a5:	e8 00 00 00 00       	call   44aa <.altinstr_replacement+0x44aa>	44a6: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
44aa     44aa:	49 bf 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r15
44b4     44b4:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
44be     44be:	e8 00 00 00 00       	call   44c3 <.altinstr_replacement+0x44c3>	44bf: R_X86_64_PLT32	copy_user_generic_string-0x4
44c3     44c3:	e8 00 00 00 00       	call   44c8 <.altinstr_replacement+0x44c8>	44c4: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
44c8     44c8:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
44d2     44d2:	0f 01 cb             	stac
44d5     44d5:	0f ae e8             	lfence
44d8     44d8:	0f 01 ca             	clac
44db     44db:	e8 00 00 00 00       	call   44e0 <.altinstr_replacement+0x44e0>	44dc: R_X86_64_PLT32	copy_user_generic_string-0x4
44e0     44e0:	e8 00 00 00 00       	call   44e5 <.altinstr_replacement+0x44e5>	44e1: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
44e5     44e5:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
44ef     44ef:	e8 00 00 00 00       	call   44f4 <.altinstr_replacement+0x44f4>	44f0: R_X86_64_PLT32	copy_user_generic_string-0x4
44f4     44f4:	e8 00 00 00 00       	call   44f9 <.altinstr_replacement+0x44f9>	44f5: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
44f9     44f9:	e8 00 00 00 00       	call   44fe <.altinstr_replacement+0x44fe>	44fa: R_X86_64_PLT32	copy_user_generic_string-0x4
44fe     44fe:	e8 00 00 00 00       	call   4503 <.altinstr_replacement+0x4503>	44ff: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
4503     4503:	e8 00 00 00 00       	call   4508 <.altinstr_replacement+0x4508>	4504: R_X86_64_PLT32	copy_user_generic_string-0x4
4508     4508:	e8 00 00 00 00       	call   450d <.altinstr_replacement+0x450d>	4509: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
450d     450d:	49 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r13
4517     4517:	49 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r13
4521     4521:	49 be 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r14
452b     452b:	0f 01 cb             	stac
452e     452e:	0f ae e8             	lfence
4531     4531:	0f 01 ca             	clac
4534     4534:	0f 01 ca             	clac
4537     4537:	e8 00 00 00 00       	call   453c <.altinstr_replacement+0x453c>	4538: R_X86_64_PLT32	copy_user_generic_string-0x4
453c     453c:	e8 00 00 00 00       	call   4541 <.altinstr_replacement+0x4541>	453d: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
4541     4541:	e8 00 00 00 00       	call   4546 <.altinstr_replacement+0x4546>	4542: R_X86_64_PLT32	copy_user_generic_string-0x4
4546     4546:	e8 00 00 00 00       	call   454b <.altinstr_replacement+0x454b>	4547: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
454b     454b:	9c                   	pushf
454c     454c:	58                   	pop    %rax
454d     454d:	fa                   	cli
454e     454e:	fb                   	sti
454f     454f:	9c                   	pushf
4550     4550:	58                   	pop    %rax
4551     4551:	f3 0f b8 c7          	popcnt %edi,%eax
4555     4555:	9c                   	pushf
4556     4556:	58                   	pop    %rax
4557     4557:	9c                   	pushf
4558     4558:	58                   	pop    %rax
4559     4559:	9c                   	pushf
455a     455a:	58                   	pop    %rax
455b     455b:	9c                   	pushf
455c     455c:	58                   	pop    %rax
455d     455d:	9c                   	pushf
455e     455e:	58                   	pop    %rax
455f     455f:	9c                   	pushf
4560     4560:	58                   	pop    %rax
4561     4561:	9c                   	pushf
4562     4562:	58                   	pop    %rax
4563     4563:	9c                   	pushf
4564     4564:	58                   	pop    %rax
4565     4565:	9c                   	pushf
4566     4566:	58                   	pop    %rax
4567     4567:	9c                   	pushf
4568     4568:	58                   	pop    %rax
4569     4569:	9c                   	pushf
456a     456a:	58                   	pop    %rax
456b     456b:	9c                   	pushf
456c     456c:	58                   	pop    %rax
456d     456d:	9c                   	pushf
456e     456e:	58                   	pop    %rax
456f     456f:	9c                   	pushf
4570     4570:	58                   	pop    %rax
4571     4571:	f3 0f b8 c7          	popcnt %edi,%eax
4575     4575:	f3 0f b8 c7          	popcnt %edi,%eax
4579     4579:	f3 0f b8 c7          	popcnt %edi,%eax
457d     457d:	f3 0f b8 c7          	popcnt %edi,%eax
4581     4581:	9c                   	pushf
4582     4582:	58                   	pop    %rax
4583     4583:	fa                   	cli
4584     4584:	fb                   	sti
4585     4585:	9c                   	pushf
4586     4586:	58                   	pop    %rax
4587     4587:	fa                   	cli
4588     4588:	9c                   	pushf
4589     4589:	58                   	pop    %rax
458a     458a:	fa                   	cli
458b     458b:	fb                   	sti
458c     458c:	9c                   	pushf
458d     458d:	58                   	pop    %rax
458e     458e:	fa                   	cli
458f     458f:	fb                   	sti
4590     4590:	f3 0f b8 c7          	popcnt %edi,%eax
4594     4594:	f3 0f b8 c7          	popcnt %edi,%eax
4598     4598:	f3 0f b8 c7          	popcnt %edi,%eax
459c     459c:	f3 0f b8 c7          	popcnt %edi,%eax
45a0     45a0:	f3 0f b8 c7          	popcnt %edi,%eax
45a4     45a4:	f3 0f b8 c7          	popcnt %edi,%eax
45a8     45a8:	f3 0f b8 c7          	popcnt %edi,%eax
45ac     45ac:	f3 0f b8 c7          	popcnt %edi,%eax
45b0     45b0:	f3 0f b8 c7          	popcnt %edi,%eax
45b4     45b4:	f3 0f b8 c7          	popcnt %edi,%eax
45b8     45b8:	f3 0f b8 c7          	popcnt %edi,%eax
45bc     45bc:	f3 0f b8 c7          	popcnt %edi,%eax
45c0     45c0:	f3 0f b8 c7          	popcnt %edi,%eax
45c4     45c4:	f3 0f b8 c7          	popcnt %edi,%eax
45c8     45c8:	f3 0f b8 c7          	popcnt %edi,%eax
45cc     45cc:	f3 0f b8 c7          	popcnt %edi,%eax
45d0     45d0:	f3 0f b8 c7          	popcnt %edi,%eax
45d4     45d4:	f3 0f b8 c7          	popcnt %edi,%eax
45d8     45d8:	f3 0f b8 c7          	popcnt %edi,%eax
45dc     45dc:	f3 0f b8 c7          	popcnt %edi,%eax
45e0     45e0:	f3 0f b8 c7          	popcnt %edi,%eax
45e4     45e4:	f3 0f b8 c7          	popcnt %edi,%eax
45e8     45e8:	f3 0f b8 c7          	popcnt %edi,%eax
45ec     45ec:	f3 0f b8 c7          	popcnt %edi,%eax
45f0     45f0:	f3 0f b8 c7          	popcnt %edi,%eax
45f4     45f4:	fb                   	sti
45f5     45f5:	9c                   	pushf
45f6     45f6:	58                   	pop    %rax
45f7     45f7:	fa                   	cli
45f8     45f8:	e8 00 00 00 00       	call   45fd <.altinstr_replacement+0x45fd>	45f9: R_X86_64_PLT32	clear_page_rep-0x4
45fd     45fd:	e8 00 00 00 00       	call   4602 <.altinstr_replacement+0x4602>	45fe: R_X86_64_PLT32	clear_page_erms-0x4
4602     4602:	0f 01 c1             	vmcall
4605     4605:	0f 01 d9             	vmmcall
4608     4608:	0f 01 c1             	vmcall
460b     460b:	0f 01 d9             	vmmcall
460e     460e:	0f 01 c1             	vmcall
4611     4611:	0f 01 d9             	vmmcall
4614     4614:	0f 01 c1             	vmcall
4617     4617:	0f 01 d9             	vmmcall
461a     461a:	0f 01 c1             	vmcall
461d     461d:	0f 01 d9             	vmmcall
4620     4620:	0f 01 c1             	vmcall
4623     4623:	0f 01 d9             	vmmcall
4626     4626:	0f 01 c1             	vmcall
4629     4629:	0f 01 d9             	vmmcall
462c     462c:	0f 01 c1             	vmcall
462f     462f:	0f 01 d9             	vmmcall
4632     4632:	0f 01 c1             	vmcall
4635     4635:	0f 01 d9             	vmmcall
4638     4638:	0f 01 c1             	vmcall
463b     463b:	0f 01 d9             	vmmcall
463e     463e:	0f 01 c1             	vmcall
4641     4641:	0f 01 d9             	vmmcall
4644     4644:	0f 01 c1             	vmcall
4647     4647:	0f 01 d9             	vmmcall
464a     464a:	0f 01 c1             	vmcall
464d     464d:	0f 01 d9             	vmmcall
4650     4650:	f3 0f b8 c7          	popcnt %edi,%eax
4654     4654:	f3 0f b8 c7          	popcnt %edi,%eax
4658     4658:	f3 0f b8 c7          	popcnt %edi,%eax
465c     465c:	f3 0f b8 c7          	popcnt %edi,%eax
4660     4660:	f3 0f b8 c7          	popcnt %edi,%eax
4664     4664:	f3 0f b8 c7          	popcnt %edi,%eax
4668     4668:	f3 0f b8 c7          	popcnt %edi,%eax
466c     466c:	f3 0f b8 c7          	popcnt %edi,%eax
4670     4670:	f3 0f b8 c7          	popcnt %edi,%eax
4674     4674:	9c                   	pushf
4675     4675:	58                   	pop    %rax
4676     4676:	9c                   	pushf
4677     4677:	58                   	pop    %rax
4678     4678:	9c                   	pushf
4679     4679:	58                   	pop    %rax
467a     467a:	9c                   	pushf
467b     467b:	58                   	pop    %rax
467c     467c:	9c                   	pushf
467d     467d:	58                   	pop    %rax
467e     467e:	9c                   	pushf
467f     467f:	58                   	pop    %rax
4680     4680:	9c                   	pushf
4681     4681:	58                   	pop    %rax
4682     4682:	9c                   	pushf
4683     4683:	58                   	pop    %rax
4684     4684:	9c                   	pushf
4685     4685:	58                   	pop    %rax
4686     4686:	e8 00 00 00 00       	call   468b <.altinstr_replacement+0x468b>	4687: R_X86_64_PLT32	clear_page_rep-0x4
468b     468b:	e8 00 00 00 00       	call   4690 <.altinstr_replacement+0x4690>	468c: R_X86_64_PLT32	clear_page_erms-0x4
4690     4690:	9c                   	pushf
4691     4691:	58                   	pop    %rax
4692     4692:	9c                   	pushf
4693     4693:	58                   	pop    %rax
4694     4694:	49 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r13
469e     469e:	9c                   	pushf
469f     469f:	58                   	pop    %rax
46a0     46a0:	fa                   	cli
46a1     46a1:	fb                   	sti
46a2     46a2:	f3 0f b8 c7          	popcnt %edi,%eax
46a6     46a6:	49 be 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r14
46b0     46b0:	f3 0f b8 c7          	popcnt %edi,%eax
46b4     46b4:	9c                   	pushf
46b5     46b5:	58                   	pop    %rax
46b6     46b6:	fa                   	cli
46b7     46b7:	9c                   	pushf
46b8     46b8:	58                   	pop    %rax
46b9     46b9:	fb                   	sti
46ba     46ba:	9c                   	pushf
46bb     46bb:	58                   	pop    %rax
46bc     46bc:	fa                   	cli
46bd     46bd:	9c                   	pushf
46be     46be:	58                   	pop    %rax
46bf     46bf:	fb                   	sti
46c0     46c0:	9c                   	pushf
46c1     46c1:	58                   	pop    %rax
46c2     46c2:	9c                   	pushf
46c3     46c3:	58                   	pop    %rax
46c4     46c4:	9c                   	pushf
46c5     46c5:	58                   	pop    %rax
46c6     46c6:	9c                   	pushf
46c7     46c7:	58                   	pop    %rax
46c8     46c8:	9c                   	pushf
46c9     46c9:	58                   	pop    %rax
46ca     46ca:	e9 00 00 00 00       	jmp    46cf <.altinstr_replacement+0x46cf>	46cb: R_X86_64_PC32	.text+0x4753c44
46cf     46cf:	e9 00 00 00 00       	jmp    46d4 <.altinstr_replacement+0x46d4>	46d0: R_X86_64_PC32	.text+0x4753c3c
46d4     46d4:	e9 00 00 00 00       	jmp    46d9 <.altinstr_replacement+0x46d9>	46d5: R_X86_64_PC32	.init.text+0x1f12bb
46d9     46d9:	f3 48 0f b8 c7       	popcnt %rdi,%rax
46de     46de:	f3 48 0f b8 c7       	popcnt %rdi,%rax
46e3     46e3:	f3 48 0f b8 c7       	popcnt %rdi,%rax
46e8     46e8:	f3 48 0f b8 c7       	popcnt %rdi,%rax
46ed     46ed:	f3 48 0f b8 c7       	popcnt %rdi,%rax
46f2     46f2:	9c                   	pushf
46f3     46f3:	58                   	pop    %rax
46f4     46f4:	fa                   	cli
46f5     46f5:	fb                   	sti
46f6     46f6:	9c                   	pushf
46f7     46f7:	58                   	pop    %rax
46f8     46f8:	fa                   	cli
46f9     46f9:	9c                   	pushf
46fa     46fa:	58                   	pop    %rax
46fb     46fb:	fb                   	sti
46fc     46fc:	9c                   	pushf
46fd     46fd:	58                   	pop    %rax
46fe     46fe:	fa                   	cli
46ff     46ff:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
4709     4709:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
4713     4713:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
471d     471d:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
4727     4727:	48 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbp
4731     4731:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
473b     473b:	49 be 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r14
4745     4745:	9c                   	pushf
4746     4746:	58                   	pop    %rax
4747     4747:	fa                   	cli
4748     4748:	9c                   	pushf
4749     4749:	58                   	pop    %rax
474a     474a:	fb                   	sti
474b     474b:	9c                   	pushf
474c     474c:	58                   	pop    %rax
474d     474d:	fa                   	cli
474e     474e:	9c                   	pushf
474f     474f:	58                   	pop    %rax
4750     4750:	fb                   	sti
4751     4751:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4756     4756:	f3 48 0f b8 c7       	popcnt %rdi,%rax
475b     475b:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4760     4760:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4765     4765:	0f 0d 4d 00          	prefetchw 0x0(%rbp)
4769     4769:	0f 0d 0b             	prefetchw (%rbx)
476c     476c:	41 0f 0d 0c 16       	prefetchw (%r14,%rdx,1)
4771     4771:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4776     4776:	f3 48 0f b8 c7       	popcnt %rdi,%rax
477b     477b:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4780     4780:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4785     4785:	e9 00 00 00 00       	jmp    478a <.altinstr_replacement+0x478a>	4786: R_X86_64_PC32	.text+0x48cea1e
478a     478a:	48 89 f8             	mov    %rdi,%rax
478d     478d:	e9 00 00 00 00       	jmp    4792 <.altinstr_replacement+0x4792>	478e: R_X86_64_PC32	.text+0x48ceaf0
4792     4792:	48 89 f8             	mov    %rdi,%rax
4795     4795:	48 89 f8             	mov    %rdi,%rax
4798     4798:	48 89 f8             	mov    %rdi,%rax
479b     479b:	48 89 f8             	mov    %rdi,%rax
479e     479e:	e9 00 00 00 00       	jmp    47a3 <.altinstr_replacement+0x47a3>	479f: R_X86_64_PC32	.text+0x48d05be
47a3     47a3:	0f 0d 8d 00 80 ff ff 	prefetchw -0x8000(%rbp)
47aa     47aa:	0f 0d 08             	prefetchw (%rax)
47ad     47ad:	41 0f 0d 4d 00       	prefetchw 0x0(%r13)
47b2     47b2:	41 0f 0d 4d 00       	prefetchw 0x0(%r13)
47b7     47b7:	e9 00 00 00 00       	jmp    47bc <.altinstr_replacement+0x47bc>	47b8: R_X86_64_PC32	.text+0x48d2472
47bc     47bc:	f3 48 0f b8 c7       	popcnt %rdi,%rax
47c1     47c1:	f3 48 0f b8 c7       	popcnt %rdi,%rax
47c6     47c6:	e9 00 00 00 00       	jmp    47cb <.altinstr_replacement+0x47cb>	47c7: R_X86_64_PC32	.text+0x48d79b2
47cb     47cb:	e9 00 00 00 00       	jmp    47d0 <.altinstr_replacement+0x47d0>	47cc: R_X86_64_PC32	.text+0x48dad2f
47d0     47d0:	e9 00 00 00 00       	jmp    47d5 <.altinstr_replacement+0x47d5>	47d1: R_X86_64_PC32	.text+0x48daef2
47d5     47d5:	f3 48 0f b8 c7       	popcnt %rdi,%rax
47da     47da:	f3 0f b8 c7          	popcnt %edi,%eax
47de     47de:	9c                   	pushf
47df     47df:	58                   	pop    %rax
47e0     47e0:	fa                   	cli
47e1     47e1:	fb                   	sti
47e2     47e2:	9c                   	pushf
47e3     47e3:	58                   	pop    %rax
47e4     47e4:	fa                   	cli
47e5     47e5:	fb                   	sti
47e6     47e6:	f3 48 0f b8 c7       	popcnt %rdi,%rax
47eb     47eb:	f3 0f b8 c7          	popcnt %edi,%eax
47ef     47ef:	49 bf 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r15
47f9     47f9:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
4803     4803:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
480d     480d:	f3 0f b8 c7          	popcnt %edi,%eax
4811     4811:	f3 0f b8 c7          	popcnt %edi,%eax
4815     4815:	f3 48 0f b8 c7       	popcnt %rdi,%rax
481a     481a:	f3 0f b8 c7          	popcnt %edi,%eax
481e     481e:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4823     4823:	f3 0f b8 c7          	popcnt %edi,%eax
4827     4827:	f3 0f b8 c7          	popcnt %edi,%eax
482b     482b:	f3 0f b8 c7          	popcnt %edi,%eax
482f     482f:	9c                   	pushf
4830     4830:	58                   	pop    %rax
4831     4831:	fa                   	cli
4832     4832:	9c                   	pushf
4833     4833:	58                   	pop    %rax
4834     4834:	fb                   	sti
4835     4835:	9c                   	pushf
4836     4836:	58                   	pop    %rax
4837     4837:	f3 48 0f b8 c7       	popcnt %rdi,%rax
483c     483c:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4841     4841:	9c                   	pushf
4842     4842:	58                   	pop    %rax
4843     4843:	fa                   	cli
4844     4844:	9c                   	pushf
4845     4845:	58                   	pop    %rax
4846     4846:	fb                   	sti
4847     4847:	9c                   	pushf
4848     4848:	58                   	pop    %rax
4849     4849:	9c                   	pushf
484a     484a:	58                   	pop    %rax
484b     484b:	fb                   	sti
484c     484c:	9c                   	pushf
484d     484d:	58                   	pop    %rax
484e     484e:	fa                   	cli
484f     484f:	9c                   	pushf
4850     4850:	58                   	pop    %rax
4851     4851:	fa                   	cli
4852     4852:	9c                   	pushf
4853     4853:	58                   	pop    %rax
4854     4854:	fb                   	sti
4855     4855:	9c                   	pushf
4856     4856:	58                   	pop    %rax
4857     4857:	fa                   	cli
4858     4858:	9c                   	pushf
4859     4859:	58                   	pop    %rax
485a     485a:	fb                   	sti
485b     485b:	9c                   	pushf
485c     485c:	58                   	pop    %rax
485d     485d:	fa                   	cli
485e     485e:	9c                   	pushf
485f     485f:	58                   	pop    %rax
4860     4860:	fb                   	sti
4861     4861:	f3 0f b8 c7          	popcnt %edi,%eax
4865     4865:	f3 0f b8 c7          	popcnt %edi,%eax
4869     4869:	9c                   	pushf
486a     486a:	58                   	pop    %rax
486b     486b:	fa                   	cli
486c     486c:	9c                   	pushf
486d     486d:	58                   	pop    %rax
486e     486e:	fb                   	sti
486f     486f:	9c                   	pushf
4870     4870:	58                   	pop    %rax
4871     4871:	fa                   	cli
4872     4872:	9c                   	pushf
4873     4873:	58                   	pop    %rax
4874     4874:	fb                   	sti
4875     4875:	9c                   	pushf
4876     4876:	58                   	pop    %rax
4877     4877:	fa                   	cli
4878     4878:	9c                   	pushf
4879     4879:	58                   	pop    %rax
487a     487a:	fb                   	sti
487b     487b:	9c                   	pushf
487c     487c:	58                   	pop    %rax
487d     487d:	fb                   	sti
487e     487e:	9c                   	pushf
487f     487f:	58                   	pop    %rax
4880     4880:	9c                   	pushf
4881     4881:	58                   	pop    %rax
4882     4882:	fa                   	cli
4883     4883:	9c                   	pushf
4884     4884:	58                   	pop    %rax
4885     4885:	fb                   	sti
4886     4886:	9c                   	pushf
4887     4887:	58                   	pop    %rax
4888     4888:	fa                   	cli
4889     4889:	9c                   	pushf
488a     488a:	58                   	pop    %rax
488b     488b:	fb                   	sti
488c     488c:	f3 0f b8 c7          	popcnt %edi,%eax
4890     4890:	9c                   	pushf
4891     4891:	58                   	pop    %rax
4892     4892:	fa                   	cli
4893     4893:	9c                   	pushf
4894     4894:	58                   	pop    %rax
4895     4895:	fb                   	sti
4896     4896:	9c                   	pushf
4897     4897:	58                   	pop    %rax
4898     4898:	fa                   	cli
4899     4899:	9c                   	pushf
489a     489a:	58                   	pop    %rax
489b     489b:	fb                   	sti
489c     489c:	9c                   	pushf
489d     489d:	58                   	pop    %rax
489e     489e:	fa                   	cli
489f     489f:	9c                   	pushf
48a0     48a0:	58                   	pop    %rax
48a1     48a1:	fb                   	sti
48a2     48a2:	9c                   	pushf
48a3     48a3:	58                   	pop    %rax
48a4     48a4:	fa                   	cli
48a5     48a5:	9c                   	pushf
48a6     48a6:	58                   	pop    %rax
48a7     48a7:	fb                   	sti
48a8     48a8:	e8 00 00 00 00       	call   48ad <.altinstr_replacement+0x48ad>	48a9: R_X86_64_PLT32	clear_page_rep-0x4
48ad     48ad:	e8 00 00 00 00       	call   48b2 <.altinstr_replacement+0x48b2>	48ae: R_X86_64_PLT32	clear_page_erms-0x4
48b2     48b2:	e8 00 00 00 00       	call   48b7 <.altinstr_replacement+0x48b7>	48b3: R_X86_64_PLT32	clear_page_rep-0x4
48b7     48b7:	e8 00 00 00 00       	call   48bc <.altinstr_replacement+0x48bc>	48b8: R_X86_64_PLT32	clear_page_erms-0x4
48bc     48bc:	e8 00 00 00 00       	call   48c1 <.altinstr_replacement+0x48c1>	48bd: R_X86_64_PLT32	clear_page_rep-0x4
48c1     48c1:	e8 00 00 00 00       	call   48c6 <.altinstr_replacement+0x48c6>	48c2: R_X86_64_PLT32	clear_page_erms-0x4
48c6     48c6:	9c                   	pushf
48c7     48c7:	58                   	pop    %rax
48c8     48c8:	fa                   	cli
48c9     48c9:	9c                   	pushf
48ca     48ca:	58                   	pop    %rax
48cb     48cb:	fb                   	sti
48cc     48cc:	f3 0f b8 c7          	popcnt %edi,%eax
48d0     48d0:	9c                   	pushf
48d1     48d1:	58                   	pop    %rax
48d2     48d2:	fa                   	cli
48d3     48d3:	9c                   	pushf
48d4     48d4:	58                   	pop    %rax
48d5     48d5:	fb                   	sti
48d6     48d6:	9c                   	pushf
48d7     48d7:	58                   	pop    %rax
48d8     48d8:	fa                   	cli
48d9     48d9:	9c                   	pushf
48da     48da:	58                   	pop    %rax
48db     48db:	fb                   	sti
48dc     48dc:	9c                   	pushf
48dd     48dd:	58                   	pop    %rax
48de     48de:	fb                   	sti
48df     48df:	9c                   	pushf
48e0     48e0:	58                   	pop    %rax
48e1     48e1:	fa                   	cli
48e2     48e2:	9c                   	pushf
48e3     48e3:	58                   	pop    %rax
48e4     48e4:	fb                   	sti
48e5     48e5:	9c                   	pushf
48e6     48e6:	58                   	pop    %rax
48e7     48e7:	fa                   	cli
48e8     48e8:	9c                   	pushf
48e9     48e9:	58                   	pop    %rax
48ea     48ea:	fb                   	sti
48eb     48eb:	9c                   	pushf
48ec     48ec:	58                   	pop    %rax
48ed     48ed:	fa                   	cli
48ee     48ee:	9c                   	pushf
48ef     48ef:	58                   	pop    %rax
48f0     48f0:	fb                   	sti
48f1     48f1:	9c                   	pushf
48f2     48f2:	58                   	pop    %rax
48f3     48f3:	f3 0f b8 c7          	popcnt %edi,%eax
48f7     48f7:	f3 0f b8 c7          	popcnt %edi,%eax
48fb     48fb:	f3 0f b8 c7          	popcnt %edi,%eax
48ff     48ff:	f3 0f b8 c7          	popcnt %edi,%eax
4903     4903:	f3 0f b8 c7          	popcnt %edi,%eax
4907     4907:	f3 0f b8 c7          	popcnt %edi,%eax
490b     490b:	f3 0f b8 c7          	popcnt %edi,%eax
490f     490f:	f3 0f b8 c7          	popcnt %edi,%eax
4913     4913:	f3 0f b8 c7          	popcnt %edi,%eax
4917     4917:	f3 48 0f b8 c7       	popcnt %rdi,%rax
491c     491c:	f3 0f b8 c7          	popcnt %edi,%eax
4920     4920:	f3 0f b8 c7          	popcnt %edi,%eax
4924     4924:	f3 0f b8 c7          	popcnt %edi,%eax
4928     4928:	f3 0f b8 c7          	popcnt %edi,%eax
492c     492c:	f3 0f b8 c7          	popcnt %edi,%eax
4930     4930:	f3 0f b8 c7          	popcnt %edi,%eax
4934     4934:	9c                   	pushf
4935     4935:	58                   	pop    %rax
4936     4936:	fa                   	cli
4937     4937:	9c                   	pushf
4938     4938:	58                   	pop    %rax
4939     4939:	fb                   	sti
493a     493a:	f3 48 0f b8 c7       	popcnt %rdi,%rax
493f     493f:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4944     4944:	f3 0f b8 c7          	popcnt %edi,%eax
4948     4948:	9c                   	pushf
4949     4949:	58                   	pop    %rax
494a     494a:	fa                   	cli
494b     494b:	9c                   	pushf
494c     494c:	58                   	pop    %rax
494d     494d:	fb                   	sti
494e     494e:	9c                   	pushf
494f     494f:	58                   	pop    %rax
4950     4950:	fa                   	cli
4951     4951:	9c                   	pushf
4952     4952:	58                   	pop    %rax
4953     4953:	fb                   	sti
4954     4954:	f3 0f b8 c7          	popcnt %edi,%eax
4958     4958:	9c                   	pushf
4959     4959:	58                   	pop    %rax
495a     495a:	9c                   	pushf
495b     495b:	58                   	pop    %rax
495c     495c:	9c                   	pushf
495d     495d:	58                   	pop    %rax
495e     495e:	9c                   	pushf
495f     495f:	58                   	pop    %rax
4960     4960:	9c                   	pushf
4961     4961:	58                   	pop    %rax
4962     4962:	9c                   	pushf
4963     4963:	58                   	pop    %rax
4964     4964:	9c                   	pushf
4965     4965:	58                   	pop    %rax
4966     4966:	9c                   	pushf
4967     4967:	58                   	pop    %rax
4968     4968:	9c                   	pushf
4969     4969:	58                   	pop    %rax
496a     496a:	9c                   	pushf
496b     496b:	58                   	pop    %rax
496c     496c:	9c                   	pushf
496d     496d:	58                   	pop    %rax
496e     496e:	fa                   	cli
496f     496f:	9c                   	pushf
4970     4970:	58                   	pop    %rax
4971     4971:	fb                   	sti
4972     4972:	9c                   	pushf
4973     4973:	58                   	pop    %rax
4974     4974:	fa                   	cli
4975     4975:	fb                   	sti
4976     4976:	f3 0f b8 c7          	popcnt %edi,%eax
497a     497a:	f3 48 0f b8 c7       	popcnt %rdi,%rax
497f     497f:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4984     4984:	9c                   	pushf
4985     4985:	58                   	pop    %rax
4986     4986:	fa                   	cli
4987     4987:	9c                   	pushf
4988     4988:	58                   	pop    %rax
4989     4989:	fb                   	sti
498a     498a:	9c                   	pushf
498b     498b:	58                   	pop    %rax
498c     498c:	fa                   	cli
498d     498d:	9c                   	pushf
498e     498e:	58                   	pop    %rax
498f     498f:	fb                   	sti
4990     4990:	9c                   	pushf
4991     4991:	58                   	pop    %rax
4992     4992:	fa                   	cli
4993     4993:	9c                   	pushf
4994     4994:	58                   	pop    %rax
4995     4995:	fa                   	cli
4996     4996:	9c                   	pushf
4997     4997:	58                   	pop    %rax
4998     4998:	fb                   	sti
4999     4999:	fb                   	sti
499a     499a:	0f 0d 8b 18 0e 00 00 	prefetchw 0xe18(%rbx)
49a1     49a1:	0f 0d 8b 1c 0e 00 00 	prefetchw 0xe1c(%rbx)
49a8     49a8:	9c                   	pushf
49a9     49a9:	58                   	pop    %rax
49aa     49aa:	fa                   	cli
49ab     49ab:	9c                   	pushf
49ac     49ac:	58                   	pop    %rax
49ad     49ad:	fb                   	sti
49ae     49ae:	9c                   	pushf
49af     49af:	58                   	pop    %rax
49b0     49b0:	fb                   	sti
49b1     49b1:	9c                   	pushf
49b2     49b2:	58                   	pop    %rax
49b3     49b3:	fb                   	sti
49b4     49b4:	9c                   	pushf
49b5     49b5:	58                   	pop    %rax
49b6     49b6:	fb                   	sti
49b7     49b7:	9c                   	pushf
49b8     49b8:	58                   	pop    %rax
49b9     49b9:	fb                   	sti
49ba     49ba:	0f 0d 8d 18 0e 00 00 	prefetchw 0xe18(%rbp)
49c1     49c1:	0f 0d 8d 1c 0e 00 00 	prefetchw 0xe1c(%rbp)
49c8     49c8:	9c                   	pushf
49c9     49c9:	58                   	pop    %rax
49ca     49ca:	fa                   	cli
49cb     49cb:	9c                   	pushf
49cc     49cc:	58                   	pop    %rax
49cd     49cd:	fb                   	sti
49ce     49ce:	41 0f 0d 0c 04       	prefetchw (%r12,%rax,1)
49d3     49d3:	0f 0d 0c 01          	prefetchw (%rcx,%rax,1)
49d7     49d7:	41 0f 0d 0c 07       	prefetchw (%r15,%rax,1)
49dc     49dc:	9c                   	pushf
49dd     49dd:	58                   	pop    %rax
49de     49de:	fa                   	cli
49df     49df:	9c                   	pushf
49e0     49e0:	58                   	pop    %rax
49e1     49e1:	fb                   	sti
49e2     49e2:	0f 0d 08             	prefetchw (%rax)
49e5     49e5:	f3 0f b8 c7          	popcnt %edi,%eax
49e9     49e9:	f3 0f b8 c7          	popcnt %edi,%eax
49ed     49ed:	f3 0f b8 c7          	popcnt %edi,%eax
49f1     49f1:	f3 0f b8 c7          	popcnt %edi,%eax
49f5     49f5:	f3 0f b8 c7          	popcnt %edi,%eax
49f9     49f9:	f3 48 0f b8 c7       	popcnt %rdi,%rax
49fe     49fe:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4a03     4a03:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4a08     4a08:	f3 0f b8 c7          	popcnt %edi,%eax
4a0c     4a0c:	9c                   	pushf
4a0d     4a0d:	58                   	pop    %rax
4a0e     4a0e:	fa                   	cli
4a0f     4a0f:	9c                   	pushf
4a10     4a10:	58                   	pop    %rax
4a11     4a11:	fb                   	sti
4a12     4a12:	9c                   	pushf
4a13     4a13:	58                   	pop    %rax
4a14     4a14:	fa                   	cli
4a15     4a15:	9c                   	pushf
4a16     4a16:	58                   	pop    %rax
4a17     4a17:	fb                   	sti
4a18     4a18:	f3 0f b8 c7          	popcnt %edi,%eax
4a1c     4a1c:	9c                   	pushf
4a1d     4a1d:	58                   	pop    %rax
4a1e     4a1e:	fa                   	cli
4a1f     4a1f:	9c                   	pushf
4a20     4a20:	58                   	pop    %rax
4a21     4a21:	fb                   	sti
4a22     4a22:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4a27     4a27:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4a2c     4a2c:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4a31     4a31:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4a36     4a36:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4a3b     4a3b:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4a40     4a40:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4a45     4a45:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4a4a     4a4a:	9c                   	pushf
4a4b     4a4b:	58                   	pop    %rax
4a4c     4a4c:	fa                   	cli
4a4d     4a4d:	9c                   	pushf
4a4e     4a4e:	58                   	pop    %rax
4a4f     4a4f:	fb                   	sti
4a50     4a50:	9c                   	pushf
4a51     4a51:	58                   	pop    %rax
4a52     4a52:	fa                   	cli
4a53     4a53:	fb                   	sti
4a54     4a54:	f3 0f b8 c7          	popcnt %edi,%eax
4a58     4a58:	f3 0f b8 c7          	popcnt %edi,%eax
4a5c     4a5c:	9c                   	pushf
4a5d     4a5d:	58                   	pop    %rax
4a5e     4a5e:	fa                   	cli
4a5f     4a5f:	9c                   	pushf
4a60     4a60:	58                   	pop    %rax
4a61     4a61:	fb                   	sti
4a62     4a62:	9c                   	pushf
4a63     4a63:	58                   	pop    %rax
4a64     4a64:	fa                   	cli
4a65     4a65:	fb                   	sti
4a66     4a66:	9c                   	pushf
4a67     4a67:	58                   	pop    %rax
4a68     4a68:	fa                   	cli
4a69     4a69:	9c                   	pushf
4a6a     4a6a:	58                   	pop    %rax
4a6b     4a6b:	fb                   	sti
4a6c     4a6c:	0f 0d 08             	prefetchw (%rax)
4a6f     4a6f:	0f 0d 08             	prefetchw (%rax)
4a72     4a72:	0f 0d 08             	prefetchw (%rax)
4a75     4a75:	0f 0d 08             	prefetchw (%rax)
4a78     4a78:	0f 0d 0b             	prefetchw (%rbx)
4a7b     4a7b:	0f 0d 08             	prefetchw (%rax)
4a7e     4a7e:	0f 0d 08             	prefetchw (%rax)
4a81     4a81:	0f 0d 08             	prefetchw (%rax)
4a84     4a84:	41 0f 0d 0c 24       	prefetchw (%r12)
4a89     4a89:	0f 0d 08             	prefetchw (%rax)
4a8c     4a8c:	f3 0f b8 c7          	popcnt %edi,%eax
4a90     4a90:	f3 0f b8 c7          	popcnt %edi,%eax
4a94     4a94:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4a99     4a99:	0f 0d 88 40 02 00 00 	prefetchw 0x240(%rax)
4aa0     4aa0:	0f 0d 88 e4 00 00 00 	prefetchw 0xe4(%rax)
4aa7     4aa7:	0f 0d 88 00 02 00 00 	prefetchw 0x200(%rax)
4aae     4aae:	0f 0d 08             	prefetchw (%rax)
4ab1     4ab1:	f3 0f b8 c7          	popcnt %edi,%eax
4ab5     4ab5:	f3 0f b8 c7          	popcnt %edi,%eax
4ab9     4ab9:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4abe     4abe:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4ac3     4ac3:	9c                   	pushf
4ac4     4ac4:	58                   	pop    %rax
4ac5     4ac5:	fa                   	cli
4ac6     4ac6:	9c                   	pushf
4ac7     4ac7:	58                   	pop    %rax
4ac8     4ac8:	fb                   	sti
4ac9     4ac9:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4ace     4ace:	0f 0d 88 e4 00 00 00 	prefetchw 0xe4(%rax)
4ad5     4ad5:	0f 0d 88 40 02 00 00 	prefetchw 0x240(%rax)
4adc     4adc:	0f 0d 88 00 02 00 00 	prefetchw 0x200(%rax)
4ae3     4ae3:	0f 0d 08             	prefetchw (%rax)
4ae6     4ae6:	0f 0d 48 40          	prefetchw 0x40(%rax)
4aea     4aea:	9c                   	pushf
4aeb     4aeb:	58                   	pop    %rax
4aec     4aec:	fa                   	cli
4aed     4aed:	9c                   	pushf
4aee     4aee:	58                   	pop    %rax
4aef     4aef:	fb                   	sti
4af0     4af0:	9c                   	pushf
4af1     4af1:	58                   	pop    %rax
4af2     4af2:	fa                   	cli
4af3     4af3:	9c                   	pushf
4af4     4af4:	58                   	pop    %rax
4af5     4af5:	fb                   	sti
4af6     4af6:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4afb     4afb:	9c                   	pushf
4afc     4afc:	58                   	pop    %rax
4afd     4afd:	fa                   	cli
4afe     4afe:	9c                   	pushf
4aff     4aff:	58                   	pop    %rax
4b00     4b00:	fb                   	sti
4b01     4b01:	0f 0d 4d 20          	prefetchw 0x20(%rbp)
4b05     4b05:	0f 0d 4d 60          	prefetchw 0x60(%rbp)
4b09     4b09:	9c                   	pushf
4b0a     4b0a:	58                   	pop    %rax
4b0b     4b0b:	fa                   	cli
4b0c     4b0c:	9c                   	pushf
4b0d     4b0d:	58                   	pop    %rax
4b0e     4b0e:	fb                   	sti
4b0f     4b0f:	0f 0d 08             	prefetchw (%rax)
4b12     4b12:	0f 0d 48 40          	prefetchw 0x40(%rax)
4b16     4b16:	0f 0d 08             	prefetchw (%rax)
4b19     4b19:	0f 0d 48 40          	prefetchw 0x40(%rax)
4b1d     4b1d:	41 0f 0d 4d 00       	prefetchw 0x0(%r13)
4b22     4b22:	41 0f 0d 4d 40       	prefetchw 0x40(%r13)
4b27     4b27:	0f 0d 4d 00          	prefetchw 0x0(%rbp)
4b2b     4b2b:	0f 0d 4d 40          	prefetchw 0x40(%rbp)
4b2f     4b2f:	41 0f 0d 08          	prefetchw (%r8)
4b33     4b33:	0f 0d 08             	prefetchw (%rax)
4b36     4b36:	41 0f 0d 4d 00       	prefetchw 0x0(%r13)
4b3b     4b3b:	41 0f 0d 4d 40       	prefetchw 0x40(%r13)
4b40     4b40:	0f 0d 4d 00          	prefetchw 0x0(%rbp)
4b44     4b44:	0f 0d 4d 40          	prefetchw 0x40(%rbp)
4b48     4b48:	0f 0d 4b 20          	prefetchw 0x20(%rbx)
4b4c     4b4c:	0f 0d 4b 60          	prefetchw 0x60(%rbx)
4b50     4b50:	f3 0f b8 c7          	popcnt %edi,%eax
4b54     4b54:	0f 0d 08             	prefetchw (%rax)
4b57     4b57:	0f 0d 48 40          	prefetchw 0x40(%rax)
4b5b     4b5b:	9c                   	pushf
4b5c     4b5c:	58                   	pop    %rax
4b5d     4b5d:	fa                   	cli
4b5e     4b5e:	9c                   	pushf
4b5f     4b5f:	58                   	pop    %rax
4b60     4b60:	fb                   	sti
4b61     4b61:	9c                   	pushf
4b62     4b62:	58                   	pop    %rax
4b63     4b63:	fa                   	cli
4b64     4b64:	9c                   	pushf
4b65     4b65:	58                   	pop    %rax
4b66     4b66:	fb                   	sti
4b67     4b67:	9c                   	pushf
4b68     4b68:	58                   	pop    %rax
4b69     4b69:	fa                   	cli
4b6a     4b6a:	9c                   	pushf
4b6b     4b6b:	58                   	pop    %rax
4b6c     4b6c:	fb                   	sti
4b6d     4b6d:	9c                   	pushf
4b6e     4b6e:	58                   	pop    %rax
4b6f     4b6f:	fa                   	cli
4b70     4b70:	9c                   	pushf
4b71     4b71:	58                   	pop    %rax
4b72     4b72:	fb                   	sti
4b73     4b73:	9c                   	pushf
4b74     4b74:	58                   	pop    %rax
4b75     4b75:	fa                   	cli
4b76     4b76:	9c                   	pushf
4b77     4b77:	58                   	pop    %rax
4b78     4b78:	fb                   	sti
4b79     4b79:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4b7e     4b7e:	0f 0d 0b             	prefetchw (%rbx)
4b81     4b81:	9c                   	pushf
4b82     4b82:	58                   	pop    %rax
4b83     4b83:	fa                   	cli
4b84     4b84:	9c                   	pushf
4b85     4b85:	58                   	pop    %rax
4b86     4b86:	fb                   	sti
4b87     4b87:	9c                   	pushf
4b88     4b88:	58                   	pop    %rax
4b89     4b89:	fa                   	cli
4b8a     4b8a:	9c                   	pushf
4b8b     4b8b:	58                   	pop    %rax
4b8c     4b8c:	fb                   	sti
4b8d     4b8d:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4b92     4b92:	41 0f 0d 0c c4       	prefetchw (%r12,%rax,8)
4b97     4b97:	f3 0f b8 c7          	popcnt %edi,%eax
4b9b     4b9b:	f3 0f b8 c7          	popcnt %edi,%eax
4b9f     4b9f:	f3 0f b8 c7          	popcnt %edi,%eax
4ba3     4ba3:	41 0f 0d 0c c4       	prefetchw (%r12,%rax,8)
4ba8     4ba8:	f3 0f b8 c7          	popcnt %edi,%eax
4bac     4bac:	f3 0f b8 c7          	popcnt %edi,%eax
4bb0     4bb0:	9c                   	pushf
4bb1     4bb1:	58                   	pop    %rax
4bb2     4bb2:	fa                   	cli
4bb3     4bb3:	9c                   	pushf
4bb4     4bb4:	58                   	pop    %rax
4bb5     4bb5:	fb                   	sti
4bb6     4bb6:	0f 0d 08             	prefetchw (%rax)
4bb9     4bb9:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4bbe     4bbe:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4bc3     4bc3:	9c                   	pushf
4bc4     4bc4:	58                   	pop    %rax
4bc5     4bc5:	fa                   	cli
4bc6     4bc6:	0f 0d 08             	prefetchw (%rax)
4bc9     4bc9:	fb                   	sti
4bca     4bca:	9c                   	pushf
4bcb     4bcb:	58                   	pop    %rax
4bcc     4bcc:	fa                   	cli
4bcd     4bcd:	fb                   	sti
4bce     4bce:	fb                   	sti
4bcf     4bcf:	9c                   	pushf
4bd0     4bd0:	58                   	pop    %rax
4bd1     4bd1:	fa                   	cli
4bd2     4bd2:	fb                   	sti
4bd3     4bd3:	9c                   	pushf
4bd4     4bd4:	58                   	pop    %rax
4bd5     4bd5:	fa                   	cli
4bd6     4bd6:	fb                   	sti
4bd7     4bd7:	9c                   	pushf
4bd8     4bd8:	58                   	pop    %rax
4bd9     4bd9:	fa                   	cli
4bda     4bda:	9c                   	pushf
4bdb     4bdb:	58                   	pop    %rax
4bdc     4bdc:	fb                   	sti
4bdd     4bdd:	9c                   	pushf
4bde     4bde:	58                   	pop    %rax
4bdf     4bdf:	fa                   	cli
4be0     4be0:	9c                   	pushf
4be1     4be1:	58                   	pop    %rax
4be2     4be2:	fb                   	sti
4be3     4be3:	f3 0f b8 c7          	popcnt %edi,%eax
4be7     4be7:	f3 0f b8 c7          	popcnt %edi,%eax
4beb     4beb:	f3 0f b8 c7          	popcnt %edi,%eax
4bef     4bef:	f3 0f b8 c7          	popcnt %edi,%eax
4bf3     4bf3:	f3 0f b8 c7          	popcnt %edi,%eax
4bf7     4bf7:	f3 0f b8 c7          	popcnt %edi,%eax
4bfb     4bfb:	f3 0f b8 c7          	popcnt %edi,%eax
4bff     4bff:	f3 0f b8 c7          	popcnt %edi,%eax
4c03     4c03:	9c                   	pushf
4c04     4c04:	58                   	pop    %rax
4c05     4c05:	fa                   	cli
4c06     4c06:	9c                   	pushf
4c07     4c07:	58                   	pop    %rax
4c08     4c08:	fb                   	sti
4c09     4c09:	f3 0f b8 c7          	popcnt %edi,%eax
4c0d     4c0d:	f3 0f b8 c7          	popcnt %edi,%eax
4c11     4c11:	f3 0f b8 c7          	popcnt %edi,%eax
4c15     4c15:	f3 0f b8 c7          	popcnt %edi,%eax
4c19     4c19:	f3 0f b8 c7          	popcnt %edi,%eax
4c1d     4c1d:	f3 0f b8 c7          	popcnt %edi,%eax
4c21     4c21:	f3 0f b8 c7          	popcnt %edi,%eax
4c25     4c25:	f3 0f b8 c7          	popcnt %edi,%eax
4c29     4c29:	9c                   	pushf
4c2a     4c2a:	58                   	pop    %rax
4c2b     4c2b:	fa                   	cli
4c2c     4c2c:	9c                   	pushf
4c2d     4c2d:	58                   	pop    %rax
4c2e     4c2e:	fb                   	sti
4c2f     4c2f:	f3 0f b8 c7          	popcnt %edi,%eax
4c33     4c33:	9c                   	pushf
4c34     4c34:	58                   	pop    %rax
4c35     4c35:	9c                   	pushf
4c36     4c36:	58                   	pop    %rax
4c37     4c37:	9c                   	pushf
4c38     4c38:	58                   	pop    %rax
4c39     4c39:	fa                   	cli
4c3a     4c3a:	9c                   	pushf
4c3b     4c3b:	58                   	pop    %rax
4c3c     4c3c:	fb                   	sti
4c3d     4c3d:	9c                   	pushf
4c3e     4c3e:	58                   	pop    %rax
4c3f     4c3f:	fa                   	cli
4c40     4c40:	9c                   	pushf
4c41     4c41:	58                   	pop    %rax
4c42     4c42:	fb                   	sti
4c43     4c43:	9c                   	pushf
4c44     4c44:	58                   	pop    %rax
4c45     4c45:	f3 0f b8 c7          	popcnt %edi,%eax
4c49     4c49:	f3 0f b8 c7          	popcnt %edi,%eax
4c4d     4c4d:	f3 0f b8 c7          	popcnt %edi,%eax
4c51     4c51:	f3 0f b8 c7          	popcnt %edi,%eax
4c55     4c55:	f3 0f b8 c7          	popcnt %edi,%eax
4c59     4c59:	f3 0f b8 c7          	popcnt %edi,%eax
4c5d     4c5d:	f3 0f b8 c7          	popcnt %edi,%eax
4c61     4c61:	f3 0f b8 c7          	popcnt %edi,%eax
4c65     4c65:	f3 0f b8 c7          	popcnt %edi,%eax
4c69     4c69:	f3 0f b8 c7          	popcnt %edi,%eax
4c6d     4c6d:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4c72     4c72:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4c77     4c77:	f3 0f b8 c7          	popcnt %edi,%eax
4c7b     4c7b:	f3 0f b8 c7          	popcnt %edi,%eax
4c7f     4c7f:	f3 0f b8 c7          	popcnt %edi,%eax
4c83     4c83:	f3 0f b8 c7          	popcnt %edi,%eax
4c87     4c87:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4c8c     4c8c:	f3 0f b8 c7          	popcnt %edi,%eax
4c90     4c90:	f3 0f b8 c7          	popcnt %edi,%eax
4c94     4c94:	f3 0f b8 c7          	popcnt %edi,%eax
4c98     4c98:	f3 0f b8 c7          	popcnt %edi,%eax
4c9c     4c9c:	f3 0f b8 c7          	popcnt %edi,%eax
4ca0     4ca0:	f3 0f b8 c7          	popcnt %edi,%eax
4ca4     4ca4:	f3 0f b8 c7          	popcnt %edi,%eax
4ca8     4ca8:	f3 0f b8 c7          	popcnt %edi,%eax
4cac     4cac:	f3 0f b8 c7          	popcnt %edi,%eax
4cb0     4cb0:	f3 0f b8 c7          	popcnt %edi,%eax
4cb4     4cb4:	f3 0f b8 c7          	popcnt %edi,%eax
4cb8     4cb8:	f3 0f b8 c7          	popcnt %edi,%eax
4cbc     4cbc:	f3 0f b8 c7          	popcnt %edi,%eax
4cc0     4cc0:	f3 0f b8 c7          	popcnt %edi,%eax
4cc4     4cc4:	f3 0f b8 c7          	popcnt %edi,%eax
4cc8     4cc8:	f3 0f b8 c7          	popcnt %edi,%eax
4ccc     4ccc:	f3 0f b8 c7          	popcnt %edi,%eax
4cd0     4cd0:	f3 0f b8 c7          	popcnt %edi,%eax
4cd4     4cd4:	f3 0f b8 c7          	popcnt %edi,%eax
4cd8     4cd8:	f3 0f b8 c7          	popcnt %edi,%eax
4cdc     4cdc:	f3 0f b8 c7          	popcnt %edi,%eax
4ce0     4ce0:	f3 0f b8 c7          	popcnt %edi,%eax
4ce4     4ce4:	f3 0f b8 c7          	popcnt %edi,%eax
4ce8     4ce8:	f3 0f b8 c7          	popcnt %edi,%eax
4cec     4cec:	f3 0f b8 c7          	popcnt %edi,%eax
4cf0     4cf0:	f3 0f b8 c7          	popcnt %edi,%eax
4cf4     4cf4:	f3 0f b8 c7          	popcnt %edi,%eax
4cf8     4cf8:	f3 0f b8 c7          	popcnt %edi,%eax
4cfc     4cfc:	f3 0f b8 c7          	popcnt %edi,%eax
4d00     4d00:	f3 0f b8 c7          	popcnt %edi,%eax
4d04     4d04:	f3 0f b8 c7          	popcnt %edi,%eax
4d08     4d08:	f3 0f b8 c7          	popcnt %edi,%eax
4d0c     4d0c:	f3 0f b8 c7          	popcnt %edi,%eax
4d10     4d10:	f3 0f b8 c7          	popcnt %edi,%eax
4d14     4d14:	f3 0f b8 c7          	popcnt %edi,%eax
4d18     4d18:	f3 0f b8 c7          	popcnt %edi,%eax
4d1c     4d1c:	f3 0f b8 c7          	popcnt %edi,%eax
4d20     4d20:	f3 0f b8 c7          	popcnt %edi,%eax
4d24     4d24:	f3 0f b8 c7          	popcnt %edi,%eax
4d28     4d28:	f3 0f b8 c7          	popcnt %edi,%eax
4d2c     4d2c:	f3 0f b8 c7          	popcnt %edi,%eax
4d30     4d30:	f3 0f b8 c7          	popcnt %edi,%eax
4d34     4d34:	f3 0f b8 c7          	popcnt %edi,%eax
4d38     4d38:	f3 0f b8 c7          	popcnt %edi,%eax
4d3c     4d3c:	f3 0f b8 c7          	popcnt %edi,%eax
4d40     4d40:	f3 0f b8 c7          	popcnt %edi,%eax
4d44     4d44:	f3 0f b8 c7          	popcnt %edi,%eax
4d48     4d48:	f3 0f b8 c7          	popcnt %edi,%eax
4d4c     4d4c:	f3 0f b8 c7          	popcnt %edi,%eax
4d50     4d50:	f3 0f b8 c7          	popcnt %edi,%eax
4d54     4d54:	f3 0f b8 c7          	popcnt %edi,%eax
4d58     4d58:	f3 0f b8 c7          	popcnt %edi,%eax
4d5c     4d5c:	f3 0f b8 c7          	popcnt %edi,%eax
4d60     4d60:	f3 0f b8 c7          	popcnt %edi,%eax
4d64     4d64:	f3 0f b8 c7          	popcnt %edi,%eax
4d68     4d68:	9c                   	pushf
4d69     4d69:	58                   	pop    %rax
4d6a     4d6a:	9c                   	pushf
4d6b     4d6b:	58                   	pop    %rax
4d6c     4d6c:	9c                   	pushf
4d6d     4d6d:	58                   	pop    %rax
4d6e     4d6e:	fb                   	sti
4d6f     4d6f:	9c                   	pushf
4d70     4d70:	58                   	pop    %rax
4d71     4d71:	fb                   	sti
4d72     4d72:	9c                   	pushf
4d73     4d73:	58                   	pop    %rax
4d74     4d74:	fb                   	sti
4d75     4d75:	9c                   	pushf
4d76     4d76:	58                   	pop    %rax
4d77     4d77:	fa                   	cli
4d78     4d78:	9c                   	pushf
4d79     4d79:	58                   	pop    %rax
4d7a     4d7a:	fb                   	sti
4d7b     4d7b:	9c                   	pushf
4d7c     4d7c:	58                   	pop    %rax
4d7d     4d7d:	fb                   	sti
4d7e     4d7e:	9c                   	pushf
4d7f     4d7f:	58                   	pop    %rax
4d80     4d80:	fb                   	sti
4d81     4d81:	9c                   	pushf
4d82     4d82:	58                   	pop    %rax
4d83     4d83:	fb                   	sti
4d84     4d84:	9c                   	pushf
4d85     4d85:	58                   	pop    %rax
4d86     4d86:	fb                   	sti
4d87     4d87:	9c                   	pushf
4d88     4d88:	58                   	pop    %rax
4d89     4d89:	fb                   	sti
4d8a     4d8a:	9c                   	pushf
4d8b     4d8b:	58                   	pop    %rax
4d8c     4d8c:	fb                   	sti
4d8d     4d8d:	9c                   	pushf
4d8e     4d8e:	58                   	pop    %rax
4d8f     4d8f:	fb                   	sti
4d90     4d90:	9c                   	pushf
4d91     4d91:	58                   	pop    %rax
4d92     4d92:	fb                   	sti
4d93     4d93:	f3 0f b8 c7          	popcnt %edi,%eax
4d97     4d97:	f3 0f b8 c7          	popcnt %edi,%eax
4d9b     4d9b:	f3 0f b8 c7          	popcnt %edi,%eax
4d9f     4d9f:	f3 0f b8 c7          	popcnt %edi,%eax
4da3     4da3:	f3 0f b8 c7          	popcnt %edi,%eax
4da7     4da7:	9c                   	pushf
4da8     4da8:	58                   	pop    %rax
4da9     4da9:	fa                   	cli
4daa     4daa:	9c                   	pushf
4dab     4dab:	58                   	pop    %rax
4dac     4dac:	fb                   	sti
4dad     4dad:	9c                   	pushf
4dae     4dae:	58                   	pop    %rax
4daf     4daf:	fa                   	cli
4db0     4db0:	9c                   	pushf
4db1     4db1:	58                   	pop    %rax
4db2     4db2:	fb                   	sti
4db3     4db3:	9c                   	pushf
4db4     4db4:	58                   	pop    %rax
4db5     4db5:	9c                   	pushf
4db6     4db6:	58                   	pop    %rax
4db7     4db7:	9c                   	pushf
4db8     4db8:	58                   	pop    %rax
4db9     4db9:	9c                   	pushf
4dba     4dba:	58                   	pop    %rax
4dbb     4dbb:	fa                   	cli
4dbc     4dbc:	9c                   	pushf
4dbd     4dbd:	58                   	pop    %rax
4dbe     4dbe:	fb                   	sti
4dbf     4dbf:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4dc4     4dc4:	9c                   	pushf
4dc5     4dc5:	58                   	pop    %rax
4dc6     4dc6:	fa                   	cli
4dc7     4dc7:	9c                   	pushf
4dc8     4dc8:	58                   	pop    %rax
4dc9     4dc9:	fb                   	sti
4dca     4dca:	9c                   	pushf
4dcb     4dcb:	58                   	pop    %rax
4dcc     4dcc:	9c                   	pushf
4dcd     4dcd:	58                   	pop    %rax
4dce     4dce:	9c                   	pushf
4dcf     4dcf:	58                   	pop    %rax
4dd0     4dd0:	fa                   	cli
4dd1     4dd1:	fb                   	sti
4dd2     4dd2:	9c                   	pushf
4dd3     4dd3:	58                   	pop    %rax
4dd4     4dd4:	fa                   	cli
4dd5     4dd5:	9c                   	pushf
4dd6     4dd6:	58                   	pop    %rax
4dd7     4dd7:	fb                   	sti
4dd8     4dd8:	9c                   	pushf
4dd9     4dd9:	58                   	pop    %rax
4dda     4dda:	fa                   	cli
4ddb     4ddb:	9c                   	pushf
4ddc     4ddc:	58                   	pop    %rax
4ddd     4ddd:	fb                   	sti
4dde     4dde:	9c                   	pushf
4ddf     4ddf:	58                   	pop    %rax
4de0     4de0:	fa                   	cli
4de1     4de1:	fb                   	sti
4de2     4de2:	f3 0f b8 c7          	popcnt %edi,%eax
4de6     4de6:	f3 0f b8 c7          	popcnt %edi,%eax
4dea     4dea:	e9 00 00 00 00       	jmp    4def <.altinstr_replacement+0x4def>	4deb: R_X86_64_PC32	.text+0x7f6501c
4def     4def:	e9 00 00 00 00       	jmp    4df4 <.altinstr_replacement+0x4df4>	4df0: R_X86_64_PC32	.text+0x7f64f05
4df4     4df4:	48 89 f8             	mov    %rdi,%rax
4df7     4df7:	49 be 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r14
4e01     4e01:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
4e0b     4e0b:	f3 0f b8 c7          	popcnt %edi,%eax
4e0f     4e0f:	9c                   	pushf
4e10     4e10:	58                   	pop    %rax
4e11     4e11:	fa                   	cli
4e12     4e12:	fb                   	sti
4e13     4e13:	49 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r13
4e1d     4e1d:	9c                   	pushf
4e1e     4e1e:	58                   	pop    %rax
4e1f     4e1f:	fa                   	cli
4e20     4e20:	fb                   	sti
4e21     4e21:	9c                   	pushf
4e22     4e22:	58                   	pop    %rax
4e23     4e23:	fa                   	cli
4e24     4e24:	9c                   	pushf
4e25     4e25:	58                   	pop    %rax
4e26     4e26:	fb                   	sti
4e27     4e27:	9c                   	pushf
4e28     4e28:	58                   	pop    %rax
4e29     4e29:	fa                   	cli
4e2a     4e2a:	9c                   	pushf
4e2b     4e2b:	58                   	pop    %rax
4e2c     4e2c:	fb                   	sti
4e2d     4e2d:	f3 0f b8 c7          	popcnt %edi,%eax
4e31     4e31:	f3 0f b8 c7          	popcnt %edi,%eax
4e35     4e35:	f3 0f b8 c7          	popcnt %edi,%eax
4e39     4e39:	f3 0f b8 c7          	popcnt %edi,%eax
4e3d     4e3d:	0f 0d 08             	prefetchw (%rax)
4e40     4e40:	9c                   	pushf
4e41     4e41:	58                   	pop    %rax
4e42     4e42:	fa                   	cli
4e43     4e43:	9c                   	pushf
4e44     4e44:	58                   	pop    %rax
4e45     4e45:	fb                   	sti
4e46     4e46:	9c                   	pushf
4e47     4e47:	58                   	pop    %rax
4e48     4e48:	9c                   	pushf
4e49     4e49:	58                   	pop    %rax
4e4a     4e4a:	fa                   	cli
4e4b     4e4b:	9c                   	pushf
4e4c     4e4c:	58                   	pop    %rax
4e4d     4e4d:	fb                   	sti
4e4e     4e4e:	9c                   	pushf
4e4f     4e4f:	58                   	pop    %rax
4e50     4e50:	fa                   	cli
4e51     4e51:	9c                   	pushf
4e52     4e52:	58                   	pop    %rax
4e53     4e53:	fb                   	sti
4e54     4e54:	9c                   	pushf
4e55     4e55:	58                   	pop    %rax
4e56     4e56:	fa                   	cli
4e57     4e57:	9c                   	pushf
4e58     4e58:	58                   	pop    %rax
4e59     4e59:	fb                   	sti
4e5a     4e5a:	0f 0d 0b             	prefetchw (%rbx)
4e5d     4e5d:	0f 0d 08             	prefetchw (%rax)
4e60     4e60:	9c                   	pushf
4e61     4e61:	58                   	pop    %rax
4e62     4e62:	fa                   	cli
4e63     4e63:	9c                   	pushf
4e64     4e64:	58                   	pop    %rax
4e65     4e65:	fb                   	sti
4e66     4e66:	0f 0d 0b             	prefetchw (%rbx)
4e69     4e69:	9c                   	pushf
4e6a     4e6a:	58                   	pop    %rax
4e6b     4e6b:	fa                   	cli
4e6c     4e6c:	9c                   	pushf
4e6d     4e6d:	58                   	pop    %rax
4e6e     4e6e:	fb                   	sti
4e6f     4e6f:	41 0f 0d 4d 00       	prefetchw 0x0(%r13)
4e74     4e74:	41 0f 0d 0e          	prefetchw (%r14)
4e78     4e78:	41 0f 0d 4d 00       	prefetchw 0x0(%r13)
4e7d     4e7d:	9c                   	pushf
4e7e     4e7e:	58                   	pop    %rax
4e7f     4e7f:	fa                   	cli
4e80     4e80:	fb                   	sti
4e81     4e81:	9c                   	pushf
4e82     4e82:	58                   	pop    %rax
4e83     4e83:	fa                   	cli
4e84     4e84:	fb                   	sti
4e85     4e85:	f3 0f b8 c7          	popcnt %edi,%eax
4e89     4e89:	f3 0f b8 c7          	popcnt %edi,%eax
4e8d     4e8d:	f3 0f b8 c7          	popcnt %edi,%eax
4e91     4e91:	9c                   	pushf
4e92     4e92:	58                   	pop    %rax
4e93     4e93:	fa                   	cli
4e94     4e94:	9c                   	pushf
4e95     4e95:	58                   	pop    %rax
4e96     4e96:	fb                   	sti
4e97     4e97:	9c                   	pushf
4e98     4e98:	58                   	pop    %rax
4e99     4e99:	fa                   	cli
4e9a     4e9a:	9c                   	pushf
4e9b     4e9b:	58                   	pop    %rax
4e9c     4e9c:	fb                   	sti
4e9d     4e9d:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4ea2     4ea2:	f3 0f b8 c7          	popcnt %edi,%eax
4ea6     4ea6:	f3 0f b8 c7          	popcnt %edi,%eax
4eaa     4eaa:	0f 01 c1             	vmcall
4ead     4ead:	0f 01 d9             	vmmcall
4eb0     4eb0:	0f 01 c1             	vmcall
4eb3     4eb3:	0f 01 d9             	vmmcall
4eb6     4eb6:	0f 01 c1             	vmcall
4eb9     4eb9:	0f 01 d9             	vmmcall
4ebc     4ebc:	0f 01 c1             	vmcall
4ebf     4ebf:	0f 01 d9             	vmmcall
4ec2     4ec2:	0f 01 c1             	vmcall
4ec5     4ec5:	0f 01 d9             	vmmcall
4ec8     4ec8:	0f 01 c1             	vmcall
4ecb     4ecb:	0f 01 d9             	vmmcall
4ece     4ece:	0f 01 c1             	vmcall
4ed1     4ed1:	0f 01 d9             	vmmcall
4ed4     4ed4:	0f 01 c1             	vmcall
4ed7     4ed7:	0f 01 d9             	vmmcall
4eda     4eda:	0f 01 c1             	vmcall
4edd     4edd:	0f 01 d9             	vmmcall
4ee0     4ee0:	0f 01 c1             	vmcall
4ee3     4ee3:	0f 01 d9             	vmmcall
4ee6     4ee6:	9c                   	pushf
4ee7     4ee7:	58                   	pop    %rax
4ee8     4ee8:	fa                   	cli
4ee9     4ee9:	9c                   	pushf
4eea     4eea:	58                   	pop    %rax
4eeb     4eeb:	fb                   	sti
4eec     4eec:	9c                   	pushf
4eed     4eed:	58                   	pop    %rax
4eee     4eee:	fa                   	cli
4eef     4eef:	9c                   	pushf
4ef0     4ef0:	58                   	pop    %rax
4ef1     4ef1:	fb                   	sti
4ef2     4ef2:	9c                   	pushf
4ef3     4ef3:	58                   	pop    %rax
4ef4     4ef4:	fa                   	cli
4ef5     4ef5:	9c                   	pushf
4ef6     4ef6:	58                   	pop    %rax
4ef7     4ef7:	9c                   	pushf
4ef8     4ef8:	58                   	pop    %rax
4ef9     4ef9:	fa                   	cli
4efa     4efa:	9c                   	pushf
4efb     4efb:	58                   	pop    %rax
4efc     4efc:	fb                   	sti
4efd     4efd:	fb                   	sti
4efe     4efe:	9c                   	pushf
4eff     4eff:	58                   	pop    %rax
4f00     4f00:	fa                   	cli
4f01     4f01:	9c                   	pushf
4f02     4f02:	58                   	pop    %rax
4f03     4f03:	fb                   	sti
4f04     4f04:	f3 0f b8 c7          	popcnt %edi,%eax
4f08     4f08:	f3 0f b8 c7          	popcnt %edi,%eax
4f0c     4f0c:	f3 0f b8 c7          	popcnt %edi,%eax
4f10     4f10:	f3 0f b8 c7          	popcnt %edi,%eax
4f14     4f14:	9c                   	pushf
4f15     4f15:	58                   	pop    %rax
4f16     4f16:	fa                   	cli
4f17     4f17:	9c                   	pushf
4f18     4f18:	58                   	pop    %rax
4f19     4f19:	fb                   	sti
4f1a     4f1a:	9c                   	pushf
4f1b     4f1b:	58                   	pop    %rax
4f1c     4f1c:	fa                   	cli
4f1d     4f1d:	9c                   	pushf
4f1e     4f1e:	58                   	pop    %rax
4f1f     4f1f:	fb                   	sti
4f20     4f20:	9c                   	pushf
4f21     4f21:	58                   	pop    %rax
4f22     4f22:	fa                   	cli
4f23     4f23:	9c                   	pushf
4f24     4f24:	58                   	pop    %rax
4f25     4f25:	fb                   	sti
4f26     4f26:	9c                   	pushf
4f27     4f27:	58                   	pop    %rax
4f28     4f28:	fa                   	cli
4f29     4f29:	9c                   	pushf
4f2a     4f2a:	58                   	pop    %rax
4f2b     4f2b:	fb                   	sti
4f2c     4f2c:	9c                   	pushf
4f2d     4f2d:	58                   	pop    %rax
4f2e     4f2e:	fa                   	cli
4f2f     4f2f:	9c                   	pushf
4f30     4f30:	58                   	pop    %rax
4f31     4f31:	fb                   	sti
4f32     4f32:	9c                   	pushf
4f33     4f33:	58                   	pop    %rax
4f34     4f34:	fa                   	cli
4f35     4f35:	9c                   	pushf
4f36     4f36:	58                   	pop    %rax
4f37     4f37:	fb                   	sti
4f38     4f38:	9c                   	pushf
4f39     4f39:	58                   	pop    %rax
4f3a     4f3a:	fa                   	cli
4f3b     4f3b:	9c                   	pushf
4f3c     4f3c:	58                   	pop    %rax
4f3d     4f3d:	fb                   	sti
4f3e     4f3e:	9c                   	pushf
4f3f     4f3f:	58                   	pop    %rax
4f40     4f40:	fa                   	cli
4f41     4f41:	9c                   	pushf
4f42     4f42:	58                   	pop    %rax
4f43     4f43:	fb                   	sti
4f44     4f44:	9c                   	pushf
4f45     4f45:	58                   	pop    %rax
4f46     4f46:	fa                   	cli
4f47     4f47:	9c                   	pushf
4f48     4f48:	58                   	pop    %rax
4f49     4f49:	fb                   	sti
4f4a     4f4a:	9c                   	pushf
4f4b     4f4b:	58                   	pop    %rax
4f4c     4f4c:	fa                   	cli
4f4d     4f4d:	9c                   	pushf
4f4e     4f4e:	58                   	pop    %rax
4f4f     4f4f:	fb                   	sti
4f50     4f50:	9c                   	pushf
4f51     4f51:	58                   	pop    %rax
4f52     4f52:	fa                   	cli
4f53     4f53:	9c                   	pushf
4f54     4f54:	58                   	pop    %rax
4f55     4f55:	fb                   	sti
4f56     4f56:	9c                   	pushf
4f57     4f57:	58                   	pop    %rax
4f58     4f58:	fa                   	cli
4f59     4f59:	9c                   	pushf
4f5a     4f5a:	58                   	pop    %rax
4f5b     4f5b:	fb                   	sti
4f5c     4f5c:	9c                   	pushf
4f5d     4f5d:	58                   	pop    %rax
4f5e     4f5e:	fa                   	cli
4f5f     4f5f:	9c                   	pushf
4f60     4f60:	58                   	pop    %rax
4f61     4f61:	fb                   	sti
4f62     4f62:	9c                   	pushf
4f63     4f63:	58                   	pop    %rax
4f64     4f64:	fa                   	cli
4f65     4f65:	9c                   	pushf
4f66     4f66:	58                   	pop    %rax
4f67     4f67:	fb                   	sti
4f68     4f68:	9c                   	pushf
4f69     4f69:	58                   	pop    %rax
4f6a     4f6a:	fa                   	cli
4f6b     4f6b:	9c                   	pushf
4f6c     4f6c:	58                   	pop    %rax
4f6d     4f6d:	fb                   	sti
4f6e     4f6e:	f3 0f b8 c7          	popcnt %edi,%eax
4f72     4f72:	f3 0f b8 c7          	popcnt %edi,%eax
4f76     4f76:	f3 0f b8 c7          	popcnt %edi,%eax
4f7a     4f7a:	f3 0f b8 c7          	popcnt %edi,%eax
4f7e     4f7e:	9c                   	pushf
4f7f     4f7f:	58                   	pop    %rax
4f80     4f80:	fa                   	cli
4f81     4f81:	fb                   	sti
4f82     4f82:	9c                   	pushf
4f83     4f83:	58                   	pop    %rax
4f84     4f84:	9c                   	pushf
4f85     4f85:	58                   	pop    %rax
4f86     4f86:	9c                   	pushf
4f87     4f87:	58                   	pop    %rax
4f88     4f88:	9c                   	pushf
4f89     4f89:	58                   	pop    %rax
4f8a     4f8a:	f3 0f b8 c7          	popcnt %edi,%eax
4f8e     4f8e:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4f93     4f93:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4f98     4f98:	f3 0f b8 c7          	popcnt %edi,%eax
4f9c     4f9c:	e8 00 00 00 00       	call   4fa1 <.altinstr_replacement+0x4fa1>	4f9d: R_X86_64_PLT32	clear_page_rep-0x4
4fa1     4fa1:	e8 00 00 00 00       	call   4fa6 <.altinstr_replacement+0x4fa6>	4fa2: R_X86_64_PLT32	clear_page_erms-0x4
4fa6     4fa6:	9c                   	pushf
4fa7     4fa7:	58                   	pop    %rax
4fa8     4fa8:	fa                   	cli
4fa9     4fa9:	9c                   	pushf
4faa     4faa:	58                   	pop    %rax
4fab     4fab:	fa                   	cli
4fac     4fac:	9c                   	pushf
4fad     4fad:	58                   	pop    %rax
4fae     4fae:	fa                   	cli
4faf     4faf:	9c                   	pushf
4fb0     4fb0:	58                   	pop    %rax
4fb1     4fb1:	fb                   	sti
4fb2     4fb2:	e9 00 00 00 00       	jmp    4fb7 <.altinstr_replacement+0x4fb7>	4fb3: R_X86_64_PC32	.text+0x8ca818d
4fb7     4fb7:	e9 00 00 00 00       	jmp    4fbc <.altinstr_replacement+0x4fbc>	4fb8: R_X86_64_PC32	.text+0x8ca8198
4fbc     4fbc:	9c                   	pushf
4fbd     4fbd:	58                   	pop    %rax
4fbe     4fbe:	fa                   	cli
4fbf     4fbf:	9c                   	pushf
4fc0     4fc0:	58                   	pop    %rax
4fc1     4fc1:	fb                   	sti
4fc2     4fc2:	9c                   	pushf
4fc3     4fc3:	58                   	pop    %rax
4fc4     4fc4:	fb                   	sti
4fc5     4fc5:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
4fcf     4fcf:	f3 0f b8 c7          	popcnt %edi,%eax
4fd3     4fd3:	f3 0f b8 c7          	popcnt %edi,%eax
4fd7     4fd7:	f3 0f b8 c7          	popcnt %edi,%eax
4fdb     4fdb:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4fe0     4fe0:	9c                   	pushf
4fe1     4fe1:	58                   	pop    %rax
4fe2     4fe2:	fa                   	cli
4fe3     4fe3:	9c                   	pushf
4fe4     4fe4:	58                   	pop    %rax
4fe5     4fe5:	fb                   	sti
4fe6     4fe6:	9c                   	pushf
4fe7     4fe7:	58                   	pop    %rax
4fe8     4fe8:	9c                   	pushf
4fe9     4fe9:	58                   	pop    %rax
4fea     4fea:	9c                   	pushf
4feb     4feb:	58                   	pop    %rax
4fec     4fec:	9c                   	pushf
4fed     4fed:	58                   	pop    %rax
4fee     4fee:	9c                   	pushf
4fef     4fef:	58                   	pop    %rax
4ff0     4ff0:	9c                   	pushf
4ff1     4ff1:	58                   	pop    %rax
4ff2     4ff2:	9c                   	pushf
4ff3     4ff3:	58                   	pop    %rax
4ff4     4ff4:	9c                   	pushf
4ff5     4ff5:	58                   	pop    %rax
4ff6     4ff6:	9c                   	pushf
4ff7     4ff7:	58                   	pop    %rax
4ff8     4ff8:	9c                   	pushf
4ff9     4ff9:	58                   	pop    %rax
4ffa     4ffa:	9c                   	pushf
4ffb     4ffb:	58                   	pop    %rax
4ffc     4ffc:	fa                   	cli
4ffd     4ffd:	9c                   	pushf
4ffe     4ffe:	58                   	pop    %rax
4fff     4fff:	fb                   	sti
5000     5000:	9c                   	pushf
5001     5001:	58                   	pop    %rax
5002     5002:	fb                   	sti
5003     5003:	9c                   	pushf
5004     5004:	58                   	pop    %rax
5005     5005:	fb                   	sti
5006     5006:	e9 00 00 00 00       	jmp    500b <.altinstr_replacement+0x500b>	5007: R_X86_64_PC32	.text+0x912b1b6
500b     500b:	0f 01 d9             	vmmcall
500e     500e:	e9 00 00 00 00       	jmp    5013 <.altinstr_replacement+0x5013>	500f: R_X86_64_PC32	.text+0x912b2d8
5013     5013:	0f 01 d9             	vmmcall
5016     5016:	e9 00 00 00 00       	jmp    501b <.altinstr_replacement+0x501b>	5017: R_X86_64_PC32	.text+0x912b50a
501b     501b:	0f 01 d9             	vmmcall
501e     501e:	0f 01 c1             	vmcall
5021     5021:	0f 01 d9             	vmmcall
5024     5024:	9c                   	pushf
5025     5025:	58                   	pop    %rax
5026     5026:	fa                   	cli
5027     5027:	9c                   	pushf
5028     5028:	58                   	pop    %rax
5029     5029:	fb                   	sti
502a     502a:	9c                   	pushf
502b     502b:	58                   	pop    %rax
502c     502c:	fa                   	cli
502d     502d:	9c                   	pushf
502e     502e:	58                   	pop    %rax
502f     502f:	fb                   	sti
5030     5030:	9c                   	pushf
5031     5031:	58                   	pop    %rax
5032     5032:	fa                   	cli
5033     5033:	9c                   	pushf
5034     5034:	58                   	pop    %rax
5035     5035:	fb                   	sti
5036     5036:	f3 0f b8 c7          	popcnt %edi,%eax
503a     503a:	f3 48 0f b8 c7       	popcnt %rdi,%rax
503f     503f:	f3 0f b8 c7          	popcnt %edi,%eax
5043     5043:	f3 0f b8 c7          	popcnt %edi,%eax
5047     5047:	f3 0f b8 c7          	popcnt %edi,%eax
504b     504b:	f3 0f b8 c7          	popcnt %edi,%eax
504f     504f:	f3 0f b8 c7          	popcnt %edi,%eax
5053     5053:	f3 0f b8 c7          	popcnt %edi,%eax
5057     5057:	f3 0f b8 c7          	popcnt %edi,%eax
505b     505b:	e9 00 00 00 00       	jmp    5060 <.altinstr_replacement+0x5060>	505c: R_X86_64_PC32	.text+0x93cdfe7
5060     5060:	f3 0f b8 c7          	popcnt %edi,%eax
5064     5064:	9c                   	pushf
5065     5065:	58                   	pop    %rax
5066     5066:	fa                   	cli
5067     5067:	9c                   	pushf
5068     5068:	58                   	pop    %rax
5069     5069:	fb                   	sti
506a     506a:	e8 00 00 00 00       	call   506f <.altinstr_replacement+0x506f>	506b: R_X86_64_PLT32	clear_page_rep-0x4
506f     506f:	e8 00 00 00 00       	call   5074 <.altinstr_replacement+0x5074>	5070: R_X86_64_PLT32	clear_page_erms-0x4
5074     5074:	e8 00 00 00 00       	call   5079 <.altinstr_replacement+0x5079>	5075: R_X86_64_PLT32	clear_page_rep-0x4
5079     5079:	e8 00 00 00 00       	call   507e <.altinstr_replacement+0x507e>	507a: R_X86_64_PLT32	clear_page_erms-0x4
507e     507e:	e8 00 00 00 00       	call   5083 <.altinstr_replacement+0x5083>	507f: R_X86_64_PLT32	clear_page_rep-0x4
5083     5083:	e8 00 00 00 00       	call   5088 <.altinstr_replacement+0x5088>	5084: R_X86_64_PLT32	clear_page_erms-0x4
5088     5088:	e8 00 00 00 00       	call   508d <.altinstr_replacement+0x508d>	5089: R_X86_64_PLT32	clear_page_rep-0x4
508d     508d:	e8 00 00 00 00       	call   5092 <.altinstr_replacement+0x5092>	508e: R_X86_64_PLT32	clear_page_erms-0x4
5092     5092:	9c                   	pushf
5093     5093:	58                   	pop    %rax
5094     5094:	fa                   	cli
5095     5095:	9c                   	pushf
5096     5096:	58                   	pop    %rax
5097     5097:	fb                   	sti
5098     5098:	f3 0f b8 c7          	popcnt %edi,%eax
509c     509c:	9c                   	pushf
509d     509d:	58                   	pop    %rax
509e     509e:	fa                   	cli
509f     509f:	9c                   	pushf
50a0     50a0:	58                   	pop    %rax
50a1     50a1:	fb                   	sti
50a2     50a2:	e9 00 00 00 00       	jmp    50a7 <.altinstr_replacement+0x50a7>	50a3: R_X86_64_PC32	.text+0x9532a5c
50a7     50a7:	9c                   	pushf
50a8     50a8:	58                   	pop    %rax
50a9     50a9:	fa                   	cli
50aa     50aa:	fb                   	sti
50ab     50ab:	9c                   	pushf
50ac     50ac:	58                   	pop    %rax
50ad     50ad:	fa                   	cli
50ae     50ae:	fb                   	sti
50af     50af:	9c                   	pushf
50b0     50b0:	58                   	pop    %rax
50b1     50b1:	fa                   	cli
50b2     50b2:	fb                   	sti
50b3     50b3:	e9 00 00 00 00       	jmp    50b8 <.altinstr_replacement+0x50b8>	50b4: R_X86_64_PC32	.init.text+0x2ae367
50b8     50b8:	e9 00 00 00 00       	jmp    50bd <.altinstr_replacement+0x50bd>	50b9: R_X86_64_PC32	.init.text+0x2ae3bd
50bd     50bd:	e9 00 00 00 00       	jmp    50c2 <.altinstr_replacement+0x50c2>	50be: R_X86_64_PC32	.init.text+0x2ae43f
50c2     50c2:	e9 00 00 00 00       	jmp    50c7 <.altinstr_replacement+0x50c7>	50c3: R_X86_64_PC32	.init.text+0x2ae48c
50c7     50c7:	9c                   	pushf
50c8     50c8:	58                   	pop    %rax
50c9     50c9:	f3 0f b8 c7          	popcnt %edi,%eax
50cd     50cd:	f3 0f b8 c7          	popcnt %edi,%eax
50d1     50d1:	f3 0f b8 c7          	popcnt %edi,%eax
50d5     50d5:	e8 00 00 00 00       	call   50da <.altinstr_replacement+0x50da>	50d6: R_X86_64_PLT32	clear_page_rep-0x4
50da     50da:	e8 00 00 00 00       	call   50df <.altinstr_replacement+0x50df>	50db: R_X86_64_PLT32	clear_page_erms-0x4
50df     50df:	e8 00 00 00 00       	call   50e4 <.altinstr_replacement+0x50e4>	50e0: R_X86_64_PLT32	clear_page_rep-0x4
50e4     50e4:	e8 00 00 00 00       	call   50e9 <.altinstr_replacement+0x50e9>	50e5: R_X86_64_PLT32	clear_page_erms-0x4
50e9     50e9:	e9 00 00 00 00       	jmp    50ee <.altinstr_replacement+0x50ee>	50ea: R_X86_64_PC32	.text+0x961566e
50ee     50ee:	66 41 0f ae 3c 24    	clflushopt (%r12)
50f4     50f4:	9c                   	pushf
50f5     50f5:	58                   	pop    %rax
50f6     50f6:	fa                   	cli
50f7     50f7:	9c                   	pushf
50f8     50f8:	58                   	pop    %rax
50f9     50f9:	fb                   	sti
50fa     50fa:	9c                   	pushf
50fb     50fb:	58                   	pop    %rax
50fc     50fc:	fa                   	cli
50fd     50fd:	9c                   	pushf
50fe     50fe:	58                   	pop    %rax
50ff     50ff:	fb                   	sti
5100     5100:	9c                   	pushf
5101     5101:	58                   	pop    %rax
5102     5102:	fa                   	cli
5103     5103:	9c                   	pushf
5104     5104:	58                   	pop    %rax
5105     5105:	fb                   	sti
5106     5106:	9c                   	pushf
5107     5107:	58                   	pop    %rax
5108     5108:	fa                   	cli
5109     5109:	9c                   	pushf
510a     510a:	58                   	pop    %rax
510b     510b:	fb                   	sti
510c     510c:	e9 00 00 00 00       	jmp    5111 <.altinstr_replacement+0x5111>	510d: R_X86_64_PC32	.text+0x97149a8
5111     5111:	e9 00 00 00 00       	jmp    5116 <.altinstr_replacement+0x5116>	5112: R_X86_64_PC32	.text+0x97147fa
5116     5116:	9c                   	pushf
5117     5117:	58                   	pop    %rax
5118     5118:	fa                   	cli
5119     5119:	9c                   	pushf
511a     511a:	58                   	pop    %rax
511b     511b:	fb                   	sti
511c     511c:	e9 00 00 00 00       	jmp    5121 <.altinstr_replacement+0x5121>	511d: R_X86_64_PC32	.init.text+0x2b3f4d
5121     5121:	e9 00 00 00 00       	jmp    5126 <.altinstr_replacement+0x5126>	5122: R_X86_64_PC32	.init.text+0x2b4b1c
5126     5126:	e9 00 00 00 00       	jmp    512b <.altinstr_replacement+0x512b>	5127: R_X86_64_PC32	.init.text+0x2b4dda
512b     512b:	f3 0f b8 c7          	popcnt %edi,%eax
512f     512f:	f3 48 0f b8 c7       	popcnt %rdi,%rax
5134     5134:	0f 09                	wbinvd
5136     5136:	f3 48 0f b8 c7       	popcnt %rdi,%rax
513b     513b:	f3 0f b8 c7          	popcnt %edi,%eax
513f     513f:	f3 0f b8 c7          	popcnt %edi,%eax
5143     5143:	f3 0f b8 c7          	popcnt %edi,%eax
5147     5147:	e9 00 00 00 00       	jmp    514c <.altinstr_replacement+0x514c>	5148: R_X86_64_PC32	.init.text+0x2b7335
514c     514c:	e9 00 00 00 00       	jmp    5151 <.altinstr_replacement+0x5151>	514d: R_X86_64_PC32	.init.text+0x2b7cd3
5151     5151:	9c                   	pushf
5152     5152:	58                   	pop    %rax
5153     5153:	9c                   	pushf
5154     5154:	58                   	pop    %rax
5155     5155:	fa                   	cli
5156     5156:	9c                   	pushf
5157     5157:	58                   	pop    %rax
5158     5158:	9c                   	pushf
5159     5159:	58                   	pop    %rax
515a     515a:	fb                   	sti
515b     515b:	fb                   	sti
515c     515c:	9c                   	pushf
515d     515d:	58                   	pop    %rax
515e     515e:	fa                   	cli
515f     515f:	9c                   	pushf
5160     5160:	58                   	pop    %rax
5161     5161:	fb                   	sti
5162     5162:	9c                   	pushf
5163     5163:	58                   	pop    %rax
5164     5164:	fa                   	cli
5165     5165:	9c                   	pushf
5166     5166:	58                   	pop    %rax
5167     5167:	fb                   	sti
5168     5168:	9c                   	pushf
5169     5169:	58                   	pop    %rax
516a     516a:	fb                   	sti
516b     516b:	9c                   	pushf
516c     516c:	58                   	pop    %rax
516d     516d:	9c                   	pushf
516e     516e:	58                   	pop    %rax
516f     516f:	fa                   	cli
5170     5170:	fb                   	sti
5171     5171:	9c                   	pushf
5172     5172:	58                   	pop    %rax
5173     5173:	fb                   	sti
5174     5174:	9c                   	pushf
5175     5175:	58                   	pop    %rax
5176     5176:	fa                   	cli
5177     5177:	fb                   	sti
5178     5178:	fb                   	sti
5179     5179:	9c                   	pushf
517a     517a:	58                   	pop    %rax
517b     517b:	fa                   	cli
517c     517c:	9c                   	pushf
517d     517d:	58                   	pop    %rax
517e     517e:	fb                   	sti
517f     517f:	9c                   	pushf
5180     5180:	58                   	pop    %rax
5181     5181:	fa                   	cli
5182     5182:	9c                   	pushf
5183     5183:	58                   	pop    %rax
5184     5184:	fb                   	sti
5185     5185:	9c                   	pushf
5186     5186:	58                   	pop    %rax
5187     5187:	fb                   	sti
5188     5188:	9c                   	pushf
5189     5189:	58                   	pop    %rax
518a     518a:	fa                   	cli
518b     518b:	9c                   	pushf
518c     518c:	58                   	pop    %rax
518d     518d:	fa                   	cli
518e     518e:	9c                   	pushf
518f     518f:	58                   	pop    %rax
5190     5190:	fb                   	sti
5191     5191:	9c                   	pushf
5192     5192:	58                   	pop    %rax
5193     5193:	fa                   	cli
5194     5194:	9c                   	pushf
5195     5195:	58                   	pop    %rax
5196     5196:	fb                   	sti
5197     5197:	9c                   	pushf
5198     5198:	58                   	pop    %rax
5199     5199:	fa                   	cli
519a     519a:	9c                   	pushf
519b     519b:	58                   	pop    %rax
519c     519c:	fb                   	sti
519d     519d:	9c                   	pushf
519e     519e:	58                   	pop    %rax
519f     519f:	fa                   	cli
51a0     51a0:	9c                   	pushf
51a1     51a1:	58                   	pop    %rax
51a2     51a2:	fb                   	sti
51a3     51a3:	9c                   	pushf
51a4     51a4:	58                   	pop    %rax
51a5     51a5:	fa                   	cli
51a6     51a6:	9c                   	pushf
51a7     51a7:	58                   	pop    %rax
51a8     51a8:	fb                   	sti
51a9     51a9:	e8 00 00 00 00       	call   51ae <.altinstr_replacement+0x51ae>	51aa: R_X86_64_PLT32	clear_page_rep-0x4
51ae     51ae:	e8 00 00 00 00       	call   51b3 <.altinstr_replacement+0x51b3>	51af: R_X86_64_PLT32	clear_page_erms-0x4
51b3     51b3:	9c                   	pushf
51b4     51b4:	58                   	pop    %rax
51b5     51b5:	fa                   	cli
51b6     51b6:	9c                   	pushf
51b7     51b7:	58                   	pop    %rax
51b8     51b8:	fb                   	sti
51b9     51b9:	9c                   	pushf
51ba     51ba:	58                   	pop    %rax
51bb     51bb:	fa                   	cli
51bc     51bc:	9c                   	pushf
51bd     51bd:	58                   	pop    %rax
51be     51be:	fb                   	sti
51bf     51bf:	9c                   	pushf
51c0     51c0:	58                   	pop    %rax
51c1     51c1:	fa                   	cli
51c2     51c2:	9c                   	pushf
51c3     51c3:	58                   	pop    %rax
51c4     51c4:	fb                   	sti
51c5     51c5:	9c                   	pushf
51c6     51c6:	58                   	pop    %rax
51c7     51c7:	fa                   	cli
51c8     51c8:	9c                   	pushf
51c9     51c9:	58                   	pop    %rax
51ca     51ca:	fb                   	sti
51cb     51cb:	f3 48 0f b8 c7       	popcnt %rdi,%rax
51d0     51d0:	9c                   	pushf
51d1     51d1:	58                   	pop    %rax
51d2     51d2:	fa                   	cli
51d3     51d3:	9c                   	pushf
51d4     51d4:	58                   	pop    %rax
51d5     51d5:	fb                   	sti
51d6     51d6:	49 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r13
51e0     51e0:	e8 00 00 00 00       	call   51e5 <.altinstr_replacement+0x51e5>	51e1: R_X86_64_PLT32	clear_page_rep-0x4
51e5     51e5:	e8 00 00 00 00       	call   51ea <.altinstr_replacement+0x51ea>	51e6: R_X86_64_PLT32	clear_page_erms-0x4
51ea     51ea:	e8 00 00 00 00       	call   51ef <.altinstr_replacement+0x51ef>	51eb: R_X86_64_PLT32	clear_page_rep-0x4
51ef     51ef:	e8 00 00 00 00       	call   51f4 <.altinstr_replacement+0x51f4>	51f0: R_X86_64_PLT32	clear_page_erms-0x4
51f4     51f4:	48 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbp
51fe     51fe:	9c                   	pushf
51ff     51ff:	58                   	pop    %rax
5200     5200:	fa                   	cli
5201     5201:	9c                   	pushf
5202     5202:	58                   	pop    %rax
5203     5203:	fb                   	sti
5204     5204:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
520e     520e:	f3 48 0f b8 c7       	popcnt %rdi,%rax
5213     5213:	9c                   	pushf
5214     5214:	58                   	pop    %rax
5215     5215:	fa                   	cli
5216     5216:	9c                   	pushf
5217     5217:	58                   	pop    %rax
5218     5218:	fb                   	sti
5219     5219:	9c                   	pushf
521a     521a:	58                   	pop    %rax
521b     521b:	fa                   	cli
521c     521c:	9c                   	pushf
521d     521d:	58                   	pop    %rax
521e     521e:	fb                   	sti
521f     521f:	f3 48 0f b8 c7       	popcnt %rdi,%rax
5224     5224:	f3 48 0f b8 c7       	popcnt %rdi,%rax
5229     5229:	f3 48 0f b8 c7       	popcnt %rdi,%rax
522e     522e:	f3 0f b8 c7          	popcnt %edi,%eax
5232     5232:	f3 0f b8 c7          	popcnt %edi,%eax
5236     5236:	f3 48 0f b8 c7       	popcnt %rdi,%rax
523b     523b:	9c                   	pushf
523c     523c:	58                   	pop    %rax
523d     523d:	fa                   	cli
523e     523e:	9c                   	pushf
523f     523f:	58                   	pop    %rax
5240     5240:	fb                   	sti
5241     5241:	9c                   	pushf
5242     5242:	58                   	pop    %rax
5243     5243:	fa                   	cli
5244     5244:	9c                   	pushf
5245     5245:	58                   	pop    %rax
5246     5246:	fb                   	sti
5247     5247:	9c                   	pushf
5248     5248:	58                   	pop    %rax
5249     5249:	fa                   	cli
524a     524a:	9c                   	pushf
524b     524b:	58                   	pop    %rax
524c     524c:	fb                   	sti
524d     524d:	9c                   	pushf
524e     524e:	58                   	pop    %rax
524f     524f:	fa                   	cli
5250     5250:	9c                   	pushf
5251     5251:	58                   	pop    %rax
5252     5252:	fb                   	sti
5253     5253:	9c                   	pushf
5254     5254:	58                   	pop    %rax
5255     5255:	fa                   	cli
5256     5256:	9c                   	pushf
5257     5257:	58                   	pop    %rax
5258     5258:	fb                   	sti
5259     5259:	9c                   	pushf
525a     525a:	58                   	pop    %rax
525b     525b:	fa                   	cli
525c     525c:	9c                   	pushf
525d     525d:	58                   	pop    %rax
525e     525e:	fb                   	sti
525f     525f:	9c                   	pushf
5260     5260:	58                   	pop    %rax
5261     5261:	fa                   	cli
5262     5262:	9c                   	pushf
5263     5263:	58                   	pop    %rax
5264     5264:	fb                   	sti
5265     5265:	9c                   	pushf
5266     5266:	58                   	pop    %rax
5267     5267:	fa                   	cli
5268     5268:	9c                   	pushf
5269     5269:	58                   	pop    %rax
526a     526a:	fb                   	sti
526b     526b:	9c                   	pushf
526c     526c:	58                   	pop    %rax
526d     526d:	9c                   	pushf
526e     526e:	58                   	pop    %rax
526f     526f:	f3 48 0f b8 c7       	popcnt %rdi,%rax
5274     5274:	9c                   	pushf
5275     5275:	58                   	pop    %rax
5276     5276:	9c                   	pushf
5277     5277:	58                   	pop    %rax
5278     5278:	fb                   	sti
5279     5279:	0f 30                	wrmsr
527b     527b:	0f 30                	wrmsr
527d     527d:	0f 30                	wrmsr
527f     527f:	0f 30                	wrmsr
5281     5281:	0f 30                	wrmsr
5283     5283:	0f 30                	wrmsr
5285     5285:	0f 30                	wrmsr
5287     5287:	0f 30                	wrmsr
5289     5289:	0f 30                	wrmsr
528b     528b:	0f 30                	wrmsr
528d     528d:	0f 30                	wrmsr
528f     528f:	0f 30                	wrmsr
5291     5291:	0f 30                	wrmsr
5293     5293:	0f 30                	wrmsr
5295     5295:	0f 30                	wrmsr
5297     5297:	0f 30                	wrmsr
5299     5299:	0f 30                	wrmsr
529b     529b:	0f 30                	wrmsr
529d     529d:	0f 30                	wrmsr
529f     529f:	0f 30                	wrmsr
52a1     52a1:	0f 30                	wrmsr
52a3     52a3:	0f 30                	wrmsr
52a5     52a5:	0f 30                	wrmsr
52a7     52a7:	0f 30                	wrmsr
52a9     52a9:	0f 30                	wrmsr
52ab     52ab:	0f 30                	wrmsr
52ad     52ad:	0f 30                	wrmsr
52af     52af:	0f 30                	wrmsr
52b1     52b1:	0f 30                	wrmsr
52b3     52b3:	0f 30                	wrmsr
52b5     52b5:	0f 30                	wrmsr
52b7     52b7:	0f 30                	wrmsr
52b9     52b9:	0f 30                	wrmsr
52bb     52bb:	0f 30                	wrmsr
52bd     52bd:	0f 30                	wrmsr
52bf     52bf:	0f 30                	wrmsr
52c1     52c1:	0f 30                	wrmsr
52c3     52c3:	0f 30                	wrmsr
52c5     52c5:	0f 30                	wrmsr
52c7     52c7:	0f 30                	wrmsr
52c9     52c9:	0f 30                	wrmsr
52cb     52cb:	0f 30                	wrmsr
52cd     52cd:	f3 48 0f b8 c7       	popcnt %rdi,%rax
52d2     52d2:	f3 48 0f b8 c7       	popcnt %rdi,%rax
52d7     52d7:	f3 48 0f b8 c7       	popcnt %rdi,%rax
52dc     52dc:	f3 48 0f b8 c7       	popcnt %rdi,%rax
52e1     52e1:	f3 0f b8 c7          	popcnt %edi,%eax
52e5     52e5:	f3 0f b8 c7          	popcnt %edi,%eax
52e9     52e9:	f3 0f b8 c7          	popcnt %edi,%eax
52ed     52ed:	f3 0f b8 c7          	popcnt %edi,%eax
52f1     52f1:	f3 0f b8 c7          	popcnt %edi,%eax
52f5     52f5:	f3 0f b8 c7          	popcnt %edi,%eax
52f9     52f9:	f3 0f b8 c7          	popcnt %edi,%eax
52fd     52fd:	f3 0f b8 c7          	popcnt %edi,%eax
5301     5301:	f3 0f b8 c7          	popcnt %edi,%eax
5305     5305:	0f ae e8             	lfence
5308     5308:	0f 31                	rdtsc
530a     530a:	0f 01 f9             	rdtscp
530d     530d:	9c                   	pushf
530e     530e:	58                   	pop    %rax
530f     530f:	fa                   	cli
5310     5310:	9c                   	pushf
5311     5311:	58                   	pop    %rax
5312     5312:	fb                   	sti
5313     5313:	9c                   	pushf
5314     5314:	58                   	pop    %rax
5315     5315:	fa                   	cli
5316     5316:	9c                   	pushf
5317     5317:	58                   	pop    %rax
5318     5318:	fb                   	sti
5319     5319:	e8 00 00 00 00       	call   531e <.altinstr_replacement+0x531e>	531a: R_X86_64_PLT32	copy_user_generic_string-0x4
531e     531e:	e8 00 00 00 00       	call   5323 <.altinstr_replacement+0x5323>	531f: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
5323     5323:	e8 00 00 00 00       	call   5328 <.altinstr_replacement+0x5328>	5324: R_X86_64_PLT32	copy_user_generic_string-0x4
5328     5328:	e8 00 00 00 00       	call   532d <.altinstr_replacement+0x532d>	5329: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
532d     532d:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
5337     5337:	48 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbp
5341     5341:	49 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r13
534b     534b:	49 bf 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r15
5355     5355:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
535f     535f:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
5369     5369:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
5373     5373:	e8 00 00 00 00       	call   5378 <.altinstr_replacement+0x5378>	5374: R_X86_64_PLT32	copy_user_generic_string-0x4
5378     5378:	e8 00 00 00 00       	call   537d <.altinstr_replacement+0x537d>	5379: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
537d     537d:	e8 00 00 00 00       	call   5382 <.altinstr_replacement+0x5382>	537e: R_X86_64_PLT32	copy_user_generic_string-0x4
5382     5382:	e8 00 00 00 00       	call   5387 <.altinstr_replacement+0x5387>	5383: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
5387     5387:	e8 00 00 00 00       	call   538c <.altinstr_replacement+0x538c>	5388: R_X86_64_PLT32	copy_user_generic_string-0x4
538c     538c:	e8 00 00 00 00       	call   5391 <.altinstr_replacement+0x5391>	538d: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
5391     5391:	e8 00 00 00 00       	call   5396 <.altinstr_replacement+0x5396>	5392: R_X86_64_PLT32	copy_user_generic_string-0x4
5396     5396:	e8 00 00 00 00       	call   539b <.altinstr_replacement+0x539b>	5397: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
539b     539b:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
53a5     53a5:	0f 09                	wbinvd
53a7     53a7:	0f 09                	wbinvd
53a9     53a9:	0f 09                	wbinvd
53ab     53ab:	f3 0f b8 c7          	popcnt %edi,%eax
53af     53af:	f3 0f b8 c7          	popcnt %edi,%eax
53b3     53b3:	e9 00 00 00 00       	jmp    53b8 <.altinstr_replacement+0x53b8>	53b4: R_X86_64_PC32	.init.text+0x319285
53b8     53b8:	49 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r13
53c2     53c2:	9c                   	pushf
53c3     53c3:	58                   	pop    %rax
53c4     53c4:	fa                   	cli
53c5     53c5:	9c                   	pushf
53c6     53c6:	58                   	pop    %rax
53c7     53c7:	9c                   	pushf
53c8     53c8:	58                   	pop    %rax
53c9     53c9:	fa                   	cli
53ca     53ca:	fb                   	sti
53cb     53cb:	f3 0f b8 c7          	popcnt %edi,%eax
53cf     53cf:	f3 0f b8 c7          	popcnt %edi,%eax
53d3     53d3:	f3 0f b8 c7          	popcnt %edi,%eax
53d7     53d7:	f3 0f b8 c7          	popcnt %edi,%eax
53db     53db:	48 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbp
53e5     53e5:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
53ef     53ef:	e8 00 00 00 00       	call   53f4 <.altinstr_replacement+0x53f4>	53f0: R_X86_64_PLT32	__x86_indirect_thunk_rbp-0x4
53f4     53f4:	0f ae e8             	lfence
53f7     53f7:	ff d5                	call   *%rbp
53f9     53f9:	e8 00 00 00 00       	call   53fe <.altinstr_replacement+0x53fe>	53fa: R_X86_64_PLT32	__x86_indirect_thunk_rax-0x4
53fe     53fe:	0f ae e8             	lfence
5401     5401:	ff d0                	call   *%rax
5403     5403:	9c                   	pushf
5404     5404:	58                   	pop    %rax
5405     5405:	fa                   	cli
5406     5406:	9c                   	pushf
5407     5407:	58                   	pop    %rax
5408     5408:	fb                   	sti
5409     5409:	e8 00 00 00 00       	call   540e <.altinstr_replacement+0x540e>	540a: R_X86_64_PLT32	__x86_indirect_thunk_r13-0x4
540e     540e:	0f ae e8             	lfence
5411     5411:	41 ff d5             	call   *%r13
5414     5414:	9c                   	pushf
5415     5415:	58                   	pop    %rax
5416     5416:	fb                   	sti
5417     5417:	e9 00 00 00 00       	jmp    541c <.altinstr_replacement+0x541c>	5418: R_X86_64_PC32	.text+0xa66e5e1
541c     541c:	e8 00 00 00 00       	call   5421 <.altinstr_replacement+0x5421>	541d: R_X86_64_PLT32	__x86_indirect_thunk_r13-0x4
5421     5421:	0f ae e8             	lfence
5424     5424:	41 ff d5             	call   *%r13
5427     5427:	9c                   	pushf
5428     5428:	58                   	pop    %rax
5429     5429:	9c                   	pushf
542a     542a:	58                   	pop    %rax
542b     542b:	fa                   	cli
542c     542c:	9c                   	pushf
542d     542d:	58                   	pop    %rax
542e     542e:	fb                   	sti
542f     542f:	f3 0f b8 c7          	popcnt %edi,%eax
5433     5433:	f3 48 0f b8 c7       	popcnt %rdi,%rax
5438     5438:	f3 48 0f b8 c7       	popcnt %rdi,%rax
543d     543d:	9c                   	pushf
543e     543e:	58                   	pop    %rax
543f     543f:	fa                   	cli
5440     5440:	9c                   	pushf
5441     5441:	58                   	pop    %rax
5442     5442:	fb                   	sti
5443     5443:	f3 0f b8 c7          	popcnt %edi,%eax
5447     5447:	f3 48 0f b8 c7       	popcnt %rdi,%rax
544c     544c:	f3 48 0f b8 c7       	popcnt %rdi,%rax
5451     5451:	f3 0f b8 c7          	popcnt %edi,%eax
5455     5455:	f3 0f b8 c7          	popcnt %edi,%eax
5459     5459:	f3 0f b8 c7          	popcnt %edi,%eax
545d     545d:	f3 0f b8 c7          	popcnt %edi,%eax
5461     5461:	f3 48 0f b8 c7       	popcnt %rdi,%rax
5466     5466:	f3 0f b8 c7          	popcnt %edi,%eax
546a     546a:	f3 48 0f b8 c7       	popcnt %rdi,%rax
546f     546f:	f3 48 0f b8 c7       	popcnt %rdi,%rax
5474     5474:	e9 00 00 00 00       	jmp    5479 <.altinstr_replacement+0x5479>	5475: R_X86_64_PC32	.text+0xa8d6847
5479     5479:	e9 00 00 00 00       	jmp    547e <.altinstr_replacement+0x547e>	547a: R_X86_64_PC32	.text+0xa8d683c
547e     547e:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
5488     5488:	9c                   	pushf
5489     5489:	58                   	pop    %rax
548a     548a:	fa                   	cli
548b     548b:	9c                   	pushf
548c     548c:	58                   	pop    %rax
548d     548d:	fb                   	sti
548e     548e:	9c                   	pushf
548f     548f:	58                   	pop    %rax
5490     5490:	fa                   	cli
5491     5491:	9c                   	pushf
5492     5492:	58                   	pop    %rax
5493     5493:	fb                   	sti
5494     5494:	9c                   	pushf
5495     5495:	58                   	pop    %rax
5496     5496:	fb                   	sti
5497     5497:	9c                   	pushf
5498     5498:	58                   	pop    %rax
5499     5499:	fa                   	cli
549a     549a:	9c                   	pushf
549b     549b:	58                   	pop    %rax
549c     549c:	fb                   	sti
549d     549d:	9c                   	pushf
549e     549e:	58                   	pop    %rax
549f     549f:	fa                   	cli
54a0     54a0:	9c                   	pushf
54a1     54a1:	58                   	pop    %rax
54a2     54a2:	fb                   	sti
54a3     54a3:	9c                   	pushf
54a4     54a4:	58                   	pop    %rax
54a5     54a5:	fa                   	cli
54a6     54a6:	9c                   	pushf
54a7     54a7:	58                   	pop    %rax
54a8     54a8:	fb                   	sti
54a9     54a9:	9c                   	pushf
54aa     54aa:	58                   	pop    %rax
54ab     54ab:	fa                   	cli
54ac     54ac:	9c                   	pushf
54ad     54ad:	58                   	pop    %rax
54ae     54ae:	fb                   	sti
54af     54af:	9c                   	pushf
54b0     54b0:	58                   	pop    %rax
54b1     54b1:	fa                   	cli
54b2     54b2:	9c                   	pushf
54b3     54b3:	58                   	pop    %rax
54b4     54b4:	fb                   	sti
54b5     54b5:	9c                   	pushf
54b6     54b6:	58                   	pop    %rax
54b7     54b7:	fa                   	cli
54b8     54b8:	9c                   	pushf
54b9     54b9:	58                   	pop    %rax
54ba     54ba:	fb                   	sti
54bb     54bb:	9c                   	pushf
54bc     54bc:	58                   	pop    %rax
54bd     54bd:	fa                   	cli
54be     54be:	9c                   	pushf
54bf     54bf:	58                   	pop    %rax
54c0     54c0:	fb                   	sti
54c1     54c1:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
54cb     54cb:	49 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r13
54d5     54d5:	9c                   	pushf
54d6     54d6:	58                   	pop    %rax
54d7     54d7:	fa                   	cli
54d8     54d8:	fb                   	sti
54d9     54d9:	9c                   	pushf
54da     54da:	58                   	pop    %rax
54db     54db:	9c                   	pushf
54dc     54dc:	58                   	pop    %rax
54dd     54dd:	9c                   	pushf
54de     54de:	58                   	pop    %rax
54df     54df:	9c                   	pushf
54e0     54e0:	58                   	pop    %rax
54e1     54e1:	9c                   	pushf
54e2     54e2:	58                   	pop    %rax
54e3     54e3:	9c                   	pushf
54e4     54e4:	58                   	pop    %rax
54e5     54e5:	9c                   	pushf
54e6     54e6:	58                   	pop    %rax
54e7     54e7:	9c                   	pushf
54e8     54e8:	58                   	pop    %rax
54e9     54e9:	9c                   	pushf
54ea     54ea:	58                   	pop    %rax
54eb     54eb:	9c                   	pushf
54ec     54ec:	58                   	pop    %rax
54ed     54ed:	9c                   	pushf
54ee     54ee:	58                   	pop    %rax
54ef     54ef:	fb                   	sti
54f0     54f0:	f3 0f b8 c7          	popcnt %edi,%eax
54f4     54f4:	f3 0f b8 c7          	popcnt %edi,%eax
54f8     54f8:	f3 0f b8 c7          	popcnt %edi,%eax
54fc     54fc:	f3 0f b8 c7          	popcnt %edi,%eax
5500     5500:	f3 48 0f b8 c7       	popcnt %rdi,%rax
5505     5505:	f3 0f b8 c7          	popcnt %edi,%eax
5509     5509:	f3 0f b8 c7          	popcnt %edi,%eax
550d     550d:	f3 48 0f b8 c7       	popcnt %rdi,%rax
5512     5512:	f3 48 0f b8 c7       	popcnt %rdi,%rax
5517     5517:	f3 48 0f b8 c7       	popcnt %rdi,%rax
551c     551c:	f3 48 0f b8 c7       	popcnt %rdi,%rax
5521     5521:	f3 48 0f b8 c7       	popcnt %rdi,%rax
5526     5526:	f3 0f b8 c7          	popcnt %edi,%eax
552a     552a:	f3 0f b8 c7          	popcnt %edi,%eax
552e     552e:	f3 0f b8 c7          	popcnt %edi,%eax
5532     5532:	f3 0f b8 c7          	popcnt %edi,%eax
5536     5536:	f3 0f b8 c7          	popcnt %edi,%eax
553a     553a:	f3 0f b8 c7          	popcnt %edi,%eax
553e     553e:	f3 0f b8 c7          	popcnt %edi,%eax
5542     5542:	f3 0f b8 c7          	popcnt %edi,%eax
5546     5546:	f3 0f b8 c7          	popcnt %edi,%eax
554a     554a:	f3 0f b8 c7          	popcnt %edi,%eax
554e     554e:	f3 0f b8 c7          	popcnt %edi,%eax
5552     5552:	f3 48 0f b8 c7       	popcnt %rdi,%rax
5557     5557:	f3 48 0f b8 c7       	popcnt %rdi,%rax
555c     555c:	f3 48 0f b8 c7       	popcnt %rdi,%rax
5561     5561:	f3 48 0f b8 c7       	popcnt %rdi,%rax
5566     5566:	f3 48 0f b8 c7       	popcnt %rdi,%rax
556b     556b:	f3 48 0f b8 c7       	popcnt %rdi,%rax
5570     5570:	f3 48 0f b8 c7       	popcnt %rdi,%rax
5575     5575:	f3 48 0f b8 c7       	popcnt %rdi,%rax
557a     557a:	f3 48 0f b8 c7       	popcnt %rdi,%rax
557f     557f:	f3 48 0f b8 c7       	popcnt %rdi,%rax
5584     5584:	f3 48 0f b8 c7       	popcnt %rdi,%rax
5589     5589:	f3 48 0f b8 c7       	popcnt %rdi,%rax
558e     558e:	f3 48 0f b8 c7       	popcnt %rdi,%rax
5593     5593:	f3 48 0f b8 c7       	popcnt %rdi,%rax
5598     5598:	f3 48 0f b8 c7       	popcnt %rdi,%rax
559d     559d:	9c                   	pushf
559e     559e:	58                   	pop    %rax
559f     559f:	41 0f 0d 0c 24       	prefetchw (%r12)
55a4     55a4:	41 0f 0d 4c 05 00    	prefetchw 0x0(%r13,%rax,1)
55aa     55aa:	9c                   	pushf
55ab     55ab:	58                   	pop    %rax
55ac     55ac:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
55b6     55b6:	0f 01 cb             	stac
55b9     55b9:	0f ae e8             	lfence
55bc     55bc:	0f 01 ca             	clac
55bf     55bf:	0f 01 ca             	clac
55c2     55c2:	9c                   	pushf
55c3     55c3:	58                   	pop    %rax
55c4     55c4:	fa                   	cli
55c5     55c5:	9c                   	pushf
55c6     55c6:	58                   	pop    %rax
55c7     55c7:	fb                   	sti
55c8     55c8:	9c                   	pushf
55c9     55c9:	58                   	pop    %rax
55ca     55ca:	fa                   	cli
55cb     55cb:	9c                   	pushf
55cc     55cc:	58                   	pop    %rax
55cd     55cd:	fb                   	sti
55ce     55ce:	9c                   	pushf
55cf     55cf:	58                   	pop    %rax
55d0     55d0:	fa                   	cli
55d1     55d1:	9c                   	pushf
55d2     55d2:	58                   	pop    %rax
55d3     55d3:	fb                   	sti
55d4     55d4:	9c                   	pushf
55d5     55d5:	58                   	pop    %rax
55d6     55d6:	fb                   	sti
55d7     55d7:	fb                   	sti
55d8     55d8:	f3 0f b8 c7          	popcnt %edi,%eax
55dc     55dc:	9c                   	pushf
55dd     55dd:	58                   	pop    %rax
55de     55de:	fa                   	cli
55df     55df:	9c                   	pushf
55e0     55e0:	58                   	pop    %rax
55e1     55e1:	fb                   	sti
55e2     55e2:	9c                   	pushf
55e3     55e3:	58                   	pop    %rax
55e4     55e4:	fa                   	cli
55e5     55e5:	fb                   	sti
55e6     55e6:	9c                   	pushf
55e7     55e7:	58                   	pop    %rax
55e8     55e8:	fa                   	cli
55e9     55e9:	fb                   	sti
55ea     55ea:	9c                   	pushf
55eb     55eb:	58                   	pop    %rax
55ec     55ec:	fa                   	cli
55ed     55ed:	fb                   	sti
55ee     55ee:	9c                   	pushf
55ef     55ef:	58                   	pop    %rax
55f0     55f0:	fa                   	cli
55f1     55f1:	9c                   	pushf
55f2     55f2:	58                   	pop    %rax
55f3     55f3:	fa                   	cli
55f4     55f4:	9c                   	pushf
55f5     55f5:	58                   	pop    %rax
55f6     55f6:	fb                   	sti
55f7     55f7:	9c                   	pushf
55f8     55f8:	58                   	pop    %rax
55f9     55f9:	fa                   	cli
55fa     55fa:	fb                   	sti
55fb     55fb:	9c                   	pushf
55fc     55fc:	58                   	pop    %rax
55fd     55fd:	fa                   	cli
55fe     55fe:	9c                   	pushf
55ff     55ff:	58                   	pop    %rax
5600     5600:	fa                   	cli
5601     5601:	9c                   	pushf
5602     5602:	58                   	pop    %rax
5603     5603:	fb                   	sti
5604     5604:	f3 0f b8 c7          	popcnt %edi,%eax
5608     5608:	9c                   	pushf
5609     5609:	58                   	pop    %rax
560a     560a:	fa                   	cli
560b     560b:	9c                   	pushf
560c     560c:	58                   	pop    %rax
560d     560d:	fb                   	sti
560e     560e:	0f 0d 08             	prefetchw (%rax)
5611     5611:	0f 0d 08             	prefetchw (%rax)
5614     5614:	9c                   	pushf
5615     5615:	58                   	pop    %rax
5616     5616:	fa                   	cli
5617     5617:	9c                   	pushf
5618     5618:	58                   	pop    %rax
5619     5619:	fb                   	sti
561a     561a:	9c                   	pushf
561b     561b:	58                   	pop    %rax
561c     561c:	fa                   	cli
561d     561d:	9c                   	pushf
561e     561e:	58                   	pop    %rax
561f     561f:	fb                   	sti
5620     5620:	9c                   	pushf
5621     5621:	58                   	pop    %rax
5622     5622:	fb                   	sti
5623     5623:	9c                   	pushf
5624     5624:	58                   	pop    %rax
5625     5625:	9c                   	pushf
5626     5626:	58                   	pop    %rax
5627     5627:	fa                   	cli
5628     5628:	9c                   	pushf
5629     5629:	58                   	pop    %rax
562a     562a:	fb                   	sti
562b     562b:	9c                   	pushf
562c     562c:	58                   	pop    %rax
562d     562d:	9c                   	pushf
562e     562e:	58                   	pop    %rax
562f     562f:	fa                   	cli
5630     5630:	0f 0d 08             	prefetchw (%rax)
5633     5633:	f3 0f b8 c7          	popcnt %edi,%eax
5637     5637:	9c                   	pushf
5638     5638:	58                   	pop    %rax
5639     5639:	fa                   	cli
563a     563a:	9c                   	pushf
563b     563b:	58                   	pop    %rax
563c     563c:	fb                   	sti
563d     563d:	f3 0f b8 c7          	popcnt %edi,%eax
5641     5641:	f3 0f b8 c7          	popcnt %edi,%eax
5645     5645:	f3 0f b8 c7          	popcnt %edi,%eax
5649     5649:	f3 48 0f b8 c7       	popcnt %rdi,%rax
564e     564e:	9c                   	pushf
564f     564f:	58                   	pop    %rax
5650     5650:	fa                   	cli
5651     5651:	9c                   	pushf
5652     5652:	58                   	pop    %rax
5653     5653:	fb                   	sti
5654     5654:	9c                   	pushf
5655     5655:	58                   	pop    %rax
5656     5656:	fa                   	cli
5657     5657:	9c                   	pushf
5658     5658:	58                   	pop    %rax
5659     5659:	fb                   	sti
565a     565a:	9c                   	pushf
565b     565b:	58                   	pop    %rax
565c     565c:	fa                   	cli
565d     565d:	9c                   	pushf
565e     565e:	58                   	pop    %rax
565f     565f:	fb                   	sti
5660     5660:	9c                   	pushf
5661     5661:	58                   	pop    %rax
5662     5662:	fa                   	cli
5663     5663:	9c                   	pushf
5664     5664:	58                   	pop    %rax
5665     5665:	fb                   	sti
5666     5666:	f3 0f b8 c7          	popcnt %edi,%eax
566a     566a:	f3 0f b8 c7          	popcnt %edi,%eax
566e     566e:	f3 0f b8 c7          	popcnt %edi,%eax
5672     5672:	9c                   	pushf
5673     5673:	58                   	pop    %rax
5674     5674:	fa                   	cli
5675     5675:	9c                   	pushf
5676     5676:	58                   	pop    %rax
5677     5677:	fb                   	sti
5678     5678:	9c                   	pushf
5679     5679:	58                   	pop    %rax
567a     567a:	fa                   	cli
567b     567b:	9c                   	pushf
567c     567c:	58                   	pop    %rax
567d     567d:	fb                   	sti
567e     567e:	9c                   	pushf
567f     567f:	58                   	pop    %rax
5680     5680:	fa                   	cli
5681     5681:	9c                   	pushf
5682     5682:	58                   	pop    %rax
5683     5683:	fb                   	sti
5684     5684:	0f 0d 08             	prefetchw (%rax)
5687     5687:	9c                   	pushf
5688     5688:	58                   	pop    %rax
5689     5689:	fa                   	cli
568a     568a:	9c                   	pushf
568b     568b:	58                   	pop    %rax
568c     568c:	fb                   	sti
568d     568d:	9c                   	pushf
568e     568e:	58                   	pop    %rax
568f     568f:	fa                   	cli
5690     5690:	9c                   	pushf
5691     5691:	58                   	pop    %rax
5692     5692:	fb                   	sti
5693     5693:	9c                   	pushf
5694     5694:	58                   	pop    %rax
5695     5695:	fa                   	cli
5696     5696:	9c                   	pushf
5697     5697:	58                   	pop    %rax
5698     5698:	fb                   	sti
5699     5699:	9c                   	pushf
569a     569a:	58                   	pop    %rax
569b     569b:	fa                   	cli
569c     569c:	9c                   	pushf
569d     569d:	58                   	pop    %rax
569e     569e:	fb                   	sti
569f     569f:	9c                   	pushf
56a0     56a0:	58                   	pop    %rax
56a1     56a1:	fa                   	cli
56a2     56a2:	9c                   	pushf
56a3     56a3:	58                   	pop    %rax
56a4     56a4:	fb                   	sti
56a5     56a5:	9c                   	pushf
56a6     56a6:	58                   	pop    %rax
56a7     56a7:	fa                   	cli
56a8     56a8:	9c                   	pushf
56a9     56a9:	58                   	pop    %rax
56aa     56aa:	fb                   	sti
56ab     56ab:	f3 0f b8 c7          	popcnt %edi,%eax
56af     56af:	9c                   	pushf
56b0     56b0:	58                   	pop    %rax
56b1     56b1:	fa                   	cli
56b2     56b2:	9c                   	pushf
56b3     56b3:	58                   	pop    %rax
56b4     56b4:	fb                   	sti
56b5     56b5:	f3 0f b8 c7          	popcnt %edi,%eax
56b9     56b9:	f3 0f b8 c7          	popcnt %edi,%eax
56bd     56bd:	f3 0f b8 c7          	popcnt %edi,%eax
56c1     56c1:	f3 0f b8 c7          	popcnt %edi,%eax
56c5     56c5:	9c                   	pushf
56c6     56c6:	58                   	pop    %rax
56c7     56c7:	fa                   	cli
56c8     56c8:	9c                   	pushf
56c9     56c9:	58                   	pop    %rax
56ca     56ca:	fb                   	sti
56cb     56cb:	f3 0f b8 c7          	popcnt %edi,%eax
56cf     56cf:	f3 0f b8 c7          	popcnt %edi,%eax
56d3     56d3:	9c                   	pushf
56d4     56d4:	58                   	pop    %rax
56d5     56d5:	fa                   	cli
56d6     56d6:	9c                   	pushf
56d7     56d7:	58                   	pop    %rax
56d8     56d8:	fb                   	sti
56d9     56d9:	9c                   	pushf
56da     56da:	58                   	pop    %rax
56db     56db:	fa                   	cli
56dc     56dc:	9c                   	pushf
56dd     56dd:	58                   	pop    %rax
56de     56de:	fb                   	sti
56df     56df:	9c                   	pushf
56e0     56e0:	58                   	pop    %rax
56e1     56e1:	fa                   	cli
56e2     56e2:	9c                   	pushf
56e3     56e3:	58                   	pop    %rax
56e4     56e4:	fb                   	sti
56e5     56e5:	9c                   	pushf
56e6     56e6:	58                   	pop    %rax
56e7     56e7:	fa                   	cli
56e8     56e8:	9c                   	pushf
56e9     56e9:	58                   	pop    %rax
56ea     56ea:	fb                   	sti
56eb     56eb:	9c                   	pushf
56ec     56ec:	58                   	pop    %rax
56ed     56ed:	fa                   	cli
56ee     56ee:	9c                   	pushf
56ef     56ef:	58                   	pop    %rax
56f0     56f0:	fb                   	sti
56f1     56f1:	9c                   	pushf
56f2     56f2:	58                   	pop    %rax
56f3     56f3:	fa                   	cli
56f4     56f4:	9c                   	pushf
56f5     56f5:	58                   	pop    %rax
56f6     56f6:	fb                   	sti
56f7     56f7:	f3 0f b8 c7          	popcnt %edi,%eax
56fb     56fb:	f3 0f b8 c7          	popcnt %edi,%eax
56ff     56ff:	f3 0f b8 c7          	popcnt %edi,%eax
5703     5703:	9c                   	pushf
5704     5704:	58                   	pop    %rax
5705     5705:	fa                   	cli
5706     5706:	9c                   	pushf
5707     5707:	58                   	pop    %rax
5708     5708:	fb                   	sti
5709     5709:	f3 0f b8 c7          	popcnt %edi,%eax
570d     570d:	f3 0f b8 c7          	popcnt %edi,%eax
5711     5711:	9c                   	pushf
5712     5712:	58                   	pop    %rax
5713     5713:	9c                   	pushf
5714     5714:	58                   	pop    %rax
5715     5715:	9c                   	pushf
5716     5716:	58                   	pop    %rax
5717     5717:	fa                   	cli
5718     5718:	9c                   	pushf
5719     5719:	58                   	pop    %rax
571a     571a:	fb                   	sti
571b     571b:	9c                   	pushf
571c     571c:	58                   	pop    %rax
571d     571d:	fa                   	cli
571e     571e:	9c                   	pushf
571f     571f:	58                   	pop    %rax
5720     5720:	fb                   	sti
5721     5721:	f3 0f b8 c7          	popcnt %edi,%eax
5725     5725:	f3 0f b8 c7          	popcnt %edi,%eax
5729     5729:	9c                   	pushf
572a     572a:	58                   	pop    %rax
572b     572b:	9c                   	pushf
572c     572c:	58                   	pop    %rax
572d     572d:	fa                   	cli
572e     572e:	9c                   	pushf
572f     572f:	58                   	pop    %rax
5730     5730:	fb                   	sti
5731     5731:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
573b     573b:	9c                   	pushf
573c     573c:	58                   	pop    %rax
573d     573d:	fa                   	cli
573e     573e:	9c                   	pushf
573f     573f:	58                   	pop    %rax
5740     5740:	fb                   	sti
5741     5741:	9c                   	pushf
5742     5742:	58                   	pop    %rax
5743     5743:	fa                   	cli
5744     5744:	9c                   	pushf
5745     5745:	58                   	pop    %rax
5746     5746:	fb                   	sti
5747     5747:	9c                   	pushf
5748     5748:	58                   	pop    %rax
5749     5749:	9c                   	pushf
574a     574a:	58                   	pop    %rax
574b     574b:	fa                   	cli
574c     574c:	9c                   	pushf
574d     574d:	58                   	pop    %rax
574e     574e:	fb                   	sti
574f     574f:	9c                   	pushf
5750     5750:	58                   	pop    %rax
5751     5751:	fb                   	sti
5752     5752:	9c                   	pushf
5753     5753:	58                   	pop    %rax
5754     5754:	fa                   	cli
5755     5755:	9c                   	pushf
5756     5756:	58                   	pop    %rax
5757     5757:	fa                   	cli
5758     5758:	9c                   	pushf
5759     5759:	58                   	pop    %rax
575a     575a:	fb                   	sti
575b     575b:	9c                   	pushf
575c     575c:	58                   	pop    %rax
575d     575d:	f3 0f b8 c7          	popcnt %edi,%eax
5761     5761:	f3 0f b8 c7          	popcnt %edi,%eax
5765     5765:	f3 0f b8 c7          	popcnt %edi,%eax
5769     5769:	f3 0f b8 c7          	popcnt %edi,%eax
576d     576d:	f3 0f b8 c7          	popcnt %edi,%eax
5771     5771:	f3 0f b8 c7          	popcnt %edi,%eax
5775     5775:	f3 0f b8 c7          	popcnt %edi,%eax
5779     5779:	f3 0f b8 c7          	popcnt %edi,%eax
577d     577d:	f3 0f b8 c7          	popcnt %edi,%eax
5781     5781:	f3 0f b8 c7          	popcnt %edi,%eax
5785     5785:	f3 48 0f b8 c7       	popcnt %rdi,%rax
578a     578a:	f3 0f b8 c7          	popcnt %edi,%eax
578e     578e:	f3 0f b8 c7          	popcnt %edi,%eax
5792     5792:	f3 0f b8 c7          	popcnt %edi,%eax
5796     5796:	f3 0f b8 c7          	popcnt %edi,%eax
579a     579a:	f3 0f b8 c7          	popcnt %edi,%eax
579e     579e:	f3 0f b8 c7          	popcnt %edi,%eax
57a2     57a2:	f3 0f b8 c7          	popcnt %edi,%eax
57a6     57a6:	f3 0f b8 c7          	popcnt %edi,%eax
57aa     57aa:	f3 0f b8 c7          	popcnt %edi,%eax
57ae     57ae:	f3 0f b8 c7          	popcnt %edi,%eax
57b2     57b2:	f3 0f b8 c7          	popcnt %edi,%eax
57b6     57b6:	f3 0f b8 c7          	popcnt %edi,%eax
57ba     57ba:	f3 0f b8 c7          	popcnt %edi,%eax
57be     57be:	f3 0f b8 c7          	popcnt %edi,%eax
57c2     57c2:	f3 0f b8 c7          	popcnt %edi,%eax
57c6     57c6:	f3 48 0f b8 c7       	popcnt %rdi,%rax
57cb     57cb:	f3 48 0f b8 c7       	popcnt %rdi,%rax
57d0     57d0:	f3 48 0f b8 c7       	popcnt %rdi,%rax
57d5     57d5:	f3 0f b8 c7          	popcnt %edi,%eax
57d9     57d9:	f3 48 0f b8 c7       	popcnt %rdi,%rax
57de     57de:	f3 48 0f b8 c7       	popcnt %rdi,%rax
57e3     57e3:	9c                   	pushf
57e4     57e4:	58                   	pop    %rax
57e5     57e5:	fa                   	cli
57e6     57e6:	9c                   	pushf
57e7     57e7:	58                   	pop    %rax
57e8     57e8:	fb                   	sti
57e9     57e9:	9c                   	pushf
57ea     57ea:	58                   	pop    %rax
57eb     57eb:	fa                   	cli
57ec     57ec:	9c                   	pushf
57ed     57ed:	58                   	pop    %rax
57ee     57ee:	fb                   	sti
57ef     57ef:	0f 20 d0             	mov    %cr2,%rax
57f2     57f2:	0f 20 d8             	mov    %cr3,%rax
57f5     57f5:	0f 22 df             	mov    %rdi,%cr3
57f8     57f8:	e9 00 00 00 00       	jmp    57fd <.altinstr_replacement+0x57fd>	57f9: R_X86_64_PC32	.text+0xc80394a
57fd     57fd:	48 89 f8             	mov    %rdi,%rax
5800     5800:	48 89 f8             	mov    %rdi,%rax
5803     5803:	48 89 f8             	mov    %rdi,%rax
5806     5806:	48 89 f8             	mov    %rdi,%rax
5809     5809:	e9 00 00 00 00       	jmp    580e <.altinstr_replacement+0x580e>	580a: R_X86_64_PC32	.text+0xc803a4a
580e     580e:	48 89 f8             	mov    %rdi,%rax
5811     5811:	e9 00 00 00 00       	jmp    5816 <.altinstr_replacement+0x5816>	5812: R_X86_64_PC32	.text+0xc803ae1
5816     5816:	e9 00 00 00 00       	jmp    581b <.altinstr_replacement+0x581b>	5817: R_X86_64_PC32	.text+0xc80421e
581b     581b:	48 89 f8             	mov    %rdi,%rax
581e     581e:	0f 20 d8             	mov    %cr3,%rax
5821     5821:	48 89 f8             	mov    %rdi,%rax
5824     5824:	48 89 f8             	mov    %rdi,%rax
5827     5827:	48 89 f8             	mov    %rdi,%rax
582a     582a:	48 89 f8             	mov    %rdi,%rax
582d     582d:	48 89 f8             	mov    %rdi,%rax
5830     5830:	48 89 f8             	mov    %rdi,%rax
5833     5833:	48 89 f8             	mov    %rdi,%rax
5836     5836:	48 89 f8             	mov    %rdi,%rax
5839     5839:	48 89 f8             	mov    %rdi,%rax
583c     583c:	48 89 f8             	mov    %rdi,%rax

-- 
0-DAY CI Kernel Test Service
https://01.org/lkp

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202209290103.pnpDQUWv-lkp%40intel.com.

--0Z4F7SWuvvF4NXmZ
Content-Type: text/plain; charset=us-ascii
Content-Disposition: attachment; filename=config

#
# Automatically generated file; DO NOT EDIT.
# Linux/x86_64 6.0.0-rc3 Kernel Configuration
#
CONFIG_CC_VERSION_TEXT="gcc-11 (Debian 11.3.0-5) 11.3.0"
CONFIG_CC_IS_GCC=y
CONFIG_GCC_VERSION=110300
CONFIG_CLANG_VERSION=0
CONFIG_AS_IS_GNU=y
CONFIG_AS_VERSION=23890
CONFIG_LD_IS_BFD=y
CONFIG_LD_VERSION=23890
CONFIG_LLD_VERSION=0
CONFIG_CC_CAN_LINK=y
CONFIG_CC_CAN_LINK_STATIC=y
CONFIG_CC_HAS_ASM_GOTO_OUTPUT=y
CONFIG_CC_HAS_ASM_INLINE=y
CONFIG_CC_HAS_NO_PROFILE_FN_ATTR=y
CONFIG_PAHOLE_VERSION=123
CONFIG_CONSTRUCTORS=y
CONFIG_IRQ_WORK=y
CONFIG_BUILDTIME_TABLE_SORT=y
CONFIG_THREAD_INFO_IN_TASK=y

#
# General setup
#
CONFIG_INIT_ENV_ARG_LIMIT=32
# CONFIG_COMPILE_TEST is not set
# CONFIG_WERROR is not set
CONFIG_UAPI_HEADER_TEST=y
CONFIG_LOCALVERSION=""
CONFIG_LOCALVERSION_AUTO=y
CONFIG_BUILD_SALT=""
CONFIG_HAVE_KERNEL_GZIP=y
CONFIG_HAVE_KERNEL_BZIP2=y
CONFIG_HAVE_KERNEL_LZMA=y
CONFIG_HAVE_KERNEL_XZ=y
CONFIG_HAVE_KERNEL_LZO=y
CONFIG_HAVE_KERNEL_LZ4=y
CONFIG_HAVE_KERNEL_ZSTD=y
CONFIG_KERNEL_GZIP=y
# CONFIG_KERNEL_BZIP2 is not set
# CONFIG_KERNEL_LZMA is not set
# CONFIG_KERNEL_XZ is not set
# CONFIG_KERNEL_LZO is not set
# CONFIG_KERNEL_LZ4 is not set
# CONFIG_KERNEL_ZSTD is not set
CONFIG_DEFAULT_INIT=""
CONFIG_DEFAULT_HOSTNAME="(none)"
CONFIG_SYSVIPC=y
CONFIG_SYSVIPC_SYSCTL=y
CONFIG_SYSVIPC_COMPAT=y
CONFIG_POSIX_MQUEUE=y
CONFIG_POSIX_MQUEUE_SYSCTL=y
CONFIG_WATCH_QUEUE=y
CONFIG_CROSS_MEMORY_ATTACH=y
CONFIG_USELIB=y
CONFIG_AUDIT=y
CONFIG_HAVE_ARCH_AUDITSYSCALL=y
CONFIG_AUDITSYSCALL=y

#
# IRQ subsystem
#
CONFIG_GENERIC_IRQ_PROBE=y
CONFIG_GENERIC_IRQ_SHOW=y
CONFIG_GENERIC_IRQ_EFFECTIVE_AFF_MASK=y
CONFIG_GENERIC_PENDING_IRQ=y
CONFIG_GENERIC_IRQ_MIGRATION=y
CONFIG_GENERIC_IRQ_INJECTION=y
CONFIG_HARDIRQS_SW_RESEND=y
CONFIG_GENERIC_IRQ_CHIP=y
CONFIG_IRQ_DOMAIN=y
CONFIG_IRQ_SIM=y
CONFIG_IRQ_DOMAIN_HIERARCHY=y
CONFIG_GENERIC_MSI_IRQ=y
CONFIG_GENERIC_MSI_IRQ_DOMAIN=y
CONFIG_IRQ_MSI_IOMMU=y
CONFIG_GENERIC_IRQ_MATRIX_ALLOCATOR=y
CONFIG_GENERIC_IRQ_RESERVATION_MODE=y
CONFIG_IRQ_FORCED_THREADING=y
CONFIG_SPARSE_IRQ=y
CONFIG_GENERIC_IRQ_DEBUGFS=y
# end of IRQ subsystem

CONFIG_CLOCKSOURCE_WATCHDOG=y
CONFIG_ARCH_CLOCKSOURCE_INIT=y
CONFIG_CLOCKSOURCE_VALIDATE_LAST_CYCLE=y
CONFIG_GENERIC_TIME_VSYSCALL=y
CONFIG_GENERIC_CLOCKEVENTS=y
CONFIG_GENERIC_CLOCKEVENTS_BROADCAST=y
CONFIG_GENERIC_CLOCKEVENTS_MIN_ADJUST=y
CONFIG_GENERIC_CMOS_UPDATE=y
CONFIG_HAVE_POSIX_CPU_TIMERS_TASK_WORK=y
CONFIG_POSIX_CPU_TIMERS_TASK_WORK=y
CONFIG_TIME_KUNIT_TEST=y
CONFIG_CONTEXT_TRACKING=y
CONFIG_CONTEXT_TRACKING_IDLE=y

#
# Timers subsystem
#
CONFIG_TICK_ONESHOT=y
CONFIG_NO_HZ_COMMON=y
# CONFIG_HZ_PERIODIC is not set
CONFIG_NO_HZ_IDLE=y
# CONFIG_NO_HZ_FULL is not set
CONFIG_NO_HZ=y
CONFIG_HIGH_RES_TIMERS=y
CONFIG_CLOCKSOURCE_WATCHDOG_MAX_SKEW_US=100
# end of Timers subsystem

CONFIG_BPF=y
CONFIG_HAVE_EBPF_JIT=y
CONFIG_ARCH_WANT_DEFAULT_BPF_JIT=y

#
# BPF subsystem
#
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
CONFIG_BPF_JIT_ALWAYS_ON=y
CONFIG_BPF_JIT_DEFAULT_ON=y
CONFIG_BPF_UNPRIV_DEFAULT_OFF=y
CONFIG_USERMODE_DRIVER=y
# CONFIG_BPF_PRELOAD is not set
CONFIG_BPF_LSM=y
# end of BPF subsystem

CONFIG_PREEMPT_BUILD=y
CONFIG_PREEMPT_NONE=y
# CONFIG_PREEMPT_VOLUNTARY is not set
# CONFIG_PREEMPT is not set
CONFIG_PREEMPT_COUNT=y
CONFIG_PREEMPTION=y
CONFIG_PREEMPT_DYNAMIC=y
CONFIG_SCHED_CORE=y

#
# CPU/Task time and stats accounting
#
CONFIG_TICK_CPU_ACCOUNTING=y
# CONFIG_VIRT_CPU_ACCOUNTING_GEN is not set
CONFIG_IRQ_TIME_ACCOUNTING=y
CONFIG_HAVE_SCHED_AVG_IRQ=y
CONFIG_BSD_PROCESS_ACCT=y
CONFIG_BSD_PROCESS_ACCT_V3=y
CONFIG_TASKSTATS=y
CONFIG_TASK_DELAY_ACCT=y
CONFIG_TASK_XACCT=y
CONFIG_TASK_IO_ACCOUNTING=y
CONFIG_PSI=y
CONFIG_PSI_DEFAULT_DISABLED=y
# end of CPU/Task time and stats accounting

CONFIG_CPU_ISOLATION=y

#
# RCU Subsystem
#
CONFIG_TREE_RCU=y
CONFIG_PREEMPT_RCU=y
CONFIG_RCU_EXPERT=y
CONFIG_SRCU=y
CONFIG_TREE_SRCU=y
CONFIG_TASKS_RCU_GENERIC=y
CONFIG_FORCE_TASKS_RCU=y
CONFIG_TASKS_RCU=y
CONFIG_FORCE_TASKS_RUDE_RCU=y
CONFIG_TASKS_RUDE_RCU=y
CONFIG_FORCE_TASKS_TRACE_RCU=y
CONFIG_TASKS_TRACE_RCU=y
CONFIG_RCU_STALL_COMMON=y
CONFIG_RCU_NEED_SEGCBLIST=y
CONFIG_RCU_FANOUT=64
CONFIG_RCU_FANOUT_LEAF=16
CONFIG_RCU_BOOST=y
CONFIG_RCU_BOOST_DELAY=500
CONFIG_RCU_EXP_KTHREAD=y
CONFIG_RCU_NOCB_CPU=y
CONFIG_RCU_NOCB_CPU_DEFAULT_ALL=y
CONFIG_RCU_NOCB_CPU_CB_BOOST=y
CONFIG_TASKS_TRACE_RCU_READ_MB=y
# end of RCU Subsystem

CONFIG_BUILD_BIN2C=y
CONFIG_IKCONFIG=y
CONFIG_IKCONFIG_PROC=y
CONFIG_IKHEADERS=y
CONFIG_LOG_BUF_SHIFT=17
CONFIG_LOG_CPU_MAX_BUF_SHIFT=12
CONFIG_PRINTK_SAFE_LOG_BUF_SHIFT=13
CONFIG_PRINTK_INDEX=y
CONFIG_HAVE_UNSTABLE_SCHED_CLOCK=y

#
# Scheduler features
#
CONFIG_UCLAMP_TASK=y
CONFIG_UCLAMP_BUCKETS_COUNT=5
# end of Scheduler features

CONFIG_ARCH_SUPPORTS_NUMA_BALANCING=y
CONFIG_ARCH_WANT_BATCHED_UNMAP_TLB_FLUSH=y
CONFIG_CC_HAS_INT128=y
CONFIG_CC_IMPLICIT_FALLTHROUGH="-Wimplicit-fallthrough=5"
CONFIG_GCC12_NO_ARRAY_BOUNDS=y
CONFIG_ARCH_SUPPORTS_INT128=y
CONFIG_NUMA_BALANCING=y
CONFIG_NUMA_BALANCING_DEFAULT_ENABLED=y
CONFIG_CGROUPS=y
CONFIG_PAGE_COUNTER=y
CONFIG_CGROUP_FAVOR_DYNMODS=y
CONFIG_MEMCG=y
CONFIG_MEMCG_KMEM=y
CONFIG_BLK_CGROUP=y
CONFIG_CGROUP_WRITEBACK=y
CONFIG_CGROUP_SCHED=y
CONFIG_FAIR_GROUP_SCHED=y
CONFIG_CFS_BANDWIDTH=y
CONFIG_RT_GROUP_SCHED=y
CONFIG_UCLAMP_TASK_GROUP=y
CONFIG_CGROUP_PIDS=y
CONFIG_CGROUP_RDMA=y
CONFIG_CGROUP_FREEZER=y
CONFIG_CGROUP_HUGETLB=y
CONFIG_CPUSETS=y
CONFIG_PROC_PID_CPUSET=y
CONFIG_CGROUP_DEVICE=y
CONFIG_CGROUP_CPUACCT=y
CONFIG_CGROUP_PERF=y
CONFIG_CGROUP_BPF=y
CONFIG_CGROUP_MISC=y
CONFIG_CGROUP_DEBUG=y
CONFIG_SOCK_CGROUP_DATA=y
CONFIG_NAMESPACES=y
CONFIG_UTS_NS=y
CONFIG_TIME_NS=y
CONFIG_IPC_NS=y
CONFIG_USER_NS=y
CONFIG_PID_NS=y
CONFIG_NET_NS=y
CONFIG_CHECKPOINT_RESTORE=y
CONFIG_SCHED_AUTOGROUP=y
CONFIG_SYSFS_DEPRECATED=y
CONFIG_SYSFS_DEPRECATED_V2=y
CONFIG_RELAY=y
CONFIG_BLK_DEV_INITRD=y
CONFIG_INITRAMFS_SOURCE=""
CONFIG_RD_GZIP=y
CONFIG_RD_BZIP2=y
CONFIG_RD_LZMA=y
CONFIG_RD_XZ=y
CONFIG_RD_LZO=y
CONFIG_RD_LZ4=y
CONFIG_RD_ZSTD=y
CONFIG_BOOT_CONFIG=y
CONFIG_BOOT_CONFIG_EMBED=y
CONFIG_BOOT_CONFIG_EMBED_FILE=""
CONFIG_INITRAMFS_PRESERVE_MTIME=y
CONFIG_CC_OPTIMIZE_FOR_PERFORMANCE=y
# CONFIG_CC_OPTIMIZE_FOR_SIZE is not set
CONFIG_LD_ORPHAN_WARN=y
CONFIG_SYSCTL=y
CONFIG_HAVE_UID16=y
CONFIG_SYSCTL_EXCEPTION_TRACE=y
CONFIG_HAVE_PCSPKR_PLATFORM=y
CONFIG_EXPERT=y
CONFIG_UID16=y
CONFIG_MULTIUSER=y
CONFIG_SGETMASK_SYSCALL=y
CONFIG_SYSFS_SYSCALL=y
CONFIG_FHANDLE=y
CONFIG_POSIX_TIMERS=y
CONFIG_PRINTK=y
CONFIG_BUG=y
CONFIG_ELF_CORE=y
CONFIG_PCSPKR_PLATFORM=y
CONFIG_BASE_FULL=y
CONFIG_FUTEX=y
CONFIG_FUTEX_PI=y
CONFIG_EPOLL=y
CONFIG_SIGNALFD=y
CONFIG_TIMERFD=y
CONFIG_EVENTFD=y
CONFIG_SHMEM=y
CONFIG_AIO=y
CONFIG_IO_URING=y
CONFIG_ADVISE_SYSCALLS=y
CONFIG_MEMBARRIER=y
CONFIG_KALLSYMS=y
CONFIG_KALLSYMS_ALL=y
CONFIG_KALLSYMS_ABSOLUTE_PERCPU=y
CONFIG_KALLSYMS_BASE_RELATIVE=y
CONFIG_ARCH_HAS_MEMBARRIER_SYNC_CORE=y
CONFIG_KCMP=y
CONFIG_RSEQ=y
CONFIG_DEBUG_RSEQ=y
CONFIG_EMBEDDED=y
CONFIG_HAVE_PERF_EVENTS=y
CONFIG_GUEST_PERF_EVENTS=y
CONFIG_PERF_USE_VMALLOC=y
CONFIG_PC104=y

#
# Kernel Performance Events And Counters
#
CONFIG_PERF_EVENTS=y
CONFIG_DEBUG_PERF_USE_VMALLOC=y
# end of Kernel Performance Events And Counters

CONFIG_SYSTEM_DATA_VERIFICATION=y
CONFIG_PROFILING=y
CONFIG_TRACEPOINTS=y
# end of General setup

CONFIG_64BIT=y
CONFIG_X86_64=y
CONFIG_X86=y
CONFIG_INSTRUCTION_DECODER=y
CONFIG_OUTPUT_FORMAT="elf64-x86-64"
CONFIG_LOCKDEP_SUPPORT=y
CONFIG_STACKTRACE_SUPPORT=y
CONFIG_MMU=y
CONFIG_ARCH_MMAP_RND_BITS_MIN=28
CONFIG_ARCH_MMAP_RND_BITS_MAX=32
CONFIG_ARCH_MMAP_RND_COMPAT_BITS_MIN=8
CONFIG_ARCH_MMAP_RND_COMPAT_BITS_MAX=16
CONFIG_GENERIC_ISA_DMA=y
CONFIG_GENERIC_CSUM=y
CONFIG_GENERIC_BUG=y
CONFIG_GENERIC_BUG_RELATIVE_POINTERS=y
CONFIG_ARCH_MAY_HAVE_PC_FDC=y
CONFIG_GENERIC_CALIBRATE_DELAY=y
CONFIG_ARCH_HAS_CPU_RELAX=y
CONFIG_ARCH_HIBERNATION_POSSIBLE=y
CONFIG_ARCH_NR_GPIO=1024
CONFIG_ARCH_SUSPEND_POSSIBLE=y
CONFIG_AUDIT_ARCH=y
CONFIG_KASAN_SHADOW_OFFSET=0xdffffc0000000000
CONFIG_HAVE_INTEL_TXT=y
CONFIG_X86_64_SMP=y
CONFIG_ARCH_SUPPORTS_UPROBES=y
CONFIG_FIX_EARLYCON_MEM=y
CONFIG_DYNAMIC_PHYSICAL_MASK=y
CONFIG_PGTABLE_LEVELS=5
CONFIG_CC_HAS_SANE_STACKPROTECTOR=y

#
# Processor type and features
#
CONFIG_SMP=y
CONFIG_X86_FEATURE_NAMES=y
CONFIG_X86_X2APIC=y
CONFIG_X86_MPPARSE=y
CONFIG_GOLDFISH=y
CONFIG_X86_CPU_RESCTRL=y
CONFIG_X86_EXTENDED_PLATFORM=y
CONFIG_X86_NUMACHIP=y
CONFIG_X86_VSMP=y
CONFIG_X86_UV=y
CONFIG_X86_GOLDFISH=y
CONFIG_X86_INTEL_MID=y
CONFIG_X86_INTEL_LPSS=y
CONFIG_X86_AMD_PLATFORM_DEVICE=y
CONFIG_IOSF_MBI=y
CONFIG_IOSF_MBI_DEBUG=y
CONFIG_X86_SUPPORTS_MEMORY_FAILURE=y
CONFIG_SCHED_OMIT_FRAME_POINTER=y
CONFIG_HYPERVISOR_GUEST=y
CONFIG_PARAVIRT=y
CONFIG_PARAVIRT_XXL=y
CONFIG_PARAVIRT_DEBUG=y
CONFIG_PARAVIRT_SPINLOCKS=y
CONFIG_X86_HV_CALLBACK_VECTOR=y
CONFIG_XEN=y
CONFIG_XEN_PV=y
CONFIG_XEN_512GB=y
CONFIG_XEN_PV_SMP=y
CONFIG_XEN_PV_DOM0=y
CONFIG_XEN_PVHVM=y
CONFIG_XEN_PVHVM_SMP=y
CONFIG_XEN_PVHVM_GUEST=y
CONFIG_XEN_SAVE_RESTORE=y
CONFIG_XEN_DEBUG_FS=y
CONFIG_XEN_PVH=y
CONFIG_XEN_DOM0=y
CONFIG_KVM_GUEST=y
CONFIG_ARCH_CPUIDLE_HALTPOLL=y
CONFIG_PVH=y
CONFIG_PARAVIRT_TIME_ACCOUNTING=y
CONFIG_PARAVIRT_CLOCK=y
CONFIG_JAILHOUSE_GUEST=y
CONFIG_ACRN_GUEST=y
CONFIG_INTEL_TDX_GUEST=y
# CONFIG_MK8 is not set
# CONFIG_MPSC is not set
# CONFIG_MCORE2 is not set
# CONFIG_MATOM is not set
CONFIG_GENERIC_CPU=y
CONFIG_X86_INTERNODE_CACHE_SHIFT=12
CONFIG_X86_L1_CACHE_SHIFT=6
CONFIG_X86_TSC=y
CONFIG_X86_CMPXCHG64=y
CONFIG_X86_CMOV=y
CONFIG_X86_MINIMUM_CPU_FAMILY=64
CONFIG_X86_DEBUGCTLMSR=y
CONFIG_IA32_FEAT_CTL=y
CONFIG_X86_VMX_FEATURE_NAMES=y
CONFIG_PROCESSOR_SELECT=y
CONFIG_CPU_SUP_INTEL=y
CONFIG_CPU_SUP_AMD=y
CONFIG_CPU_SUP_HYGON=y
CONFIG_CPU_SUP_CENTAUR=y
CONFIG_CPU_SUP_ZHAOXIN=y
CONFIG_HPET_TIMER=y
CONFIG_HPET_EMULATE_RTC=y
CONFIG_DMI=y
CONFIG_GART_IOMMU=y
CONFIG_BOOT_VESA_SUPPORT=y
CONFIG_MAXSMP=y
CONFIG_NR_CPUS_RANGE_BEGIN=8192
CONFIG_NR_CPUS_RANGE_END=8192
CONFIG_NR_CPUS_DEFAULT=8192
CONFIG_NR_CPUS=8192
CONFIG_SCHED_CLUSTER=y
CONFIG_SCHED_SMT=y
CONFIG_SCHED_MC=y
CONFIG_SCHED_MC_PRIO=y
CONFIG_X86_LOCAL_APIC=y
CONFIG_X86_IO_APIC=y
CONFIG_X86_REROUTE_FOR_BROKEN_BOOT_IRQS=y
CONFIG_X86_MCE=y
CONFIG_X86_MCELOG_LEGACY=y
CONFIG_X86_MCE_INTEL=y
CONFIG_X86_MCE_AMD=y
CONFIG_X86_MCE_THRESHOLD=y
CONFIG_X86_MCE_INJECT=y

#
# Performance monitoring
#
CONFIG_PERF_EVENTS_INTEL_UNCORE=y
CONFIG_PERF_EVENTS_INTEL_RAPL=y
CONFIG_PERF_EVENTS_INTEL_CSTATE=y
CONFIG_PERF_EVENTS_AMD_POWER=y
CONFIG_PERF_EVENTS_AMD_UNCORE=y
CONFIG_PERF_EVENTS_AMD_BRS=y
# end of Performance monitoring

CONFIG_X86_16BIT=y
CONFIG_X86_ESPFIX64=y
CONFIG_X86_VSYSCALL_EMULATION=y
CONFIG_X86_IOPL_IOPERM=y
CONFIG_MICROCODE=y
CONFIG_MICROCODE_INTEL=y
CONFIG_MICROCODE_AMD=y
CONFIG_MICROCODE_LATE_LOADING=y
CONFIG_X86_MSR=y
CONFIG_X86_CPUID=y
CONFIG_X86_5LEVEL=y
CONFIG_X86_DIRECT_GBPAGES=y
CONFIG_X86_CPA_STATISTICS=y
CONFIG_X86_MEM_ENCRYPT=y
CONFIG_AMD_MEM_ENCRYPT=y
CONFIG_AMD_MEM_ENCRYPT_ACTIVE_BY_DEFAULT=y
CONFIG_NUMA=y
CONFIG_AMD_NUMA=y
CONFIG_X86_64_ACPI_NUMA=y
CONFIG_NUMA_EMU=y
CONFIG_NODES_SHIFT=10
CONFIG_ARCH_SPARSEMEM_ENABLE=y
CONFIG_ARCH_SPARSEMEM_DEFAULT=y
CONFIG_ARCH_MEMORY_PROBE=y
CONFIG_ARCH_PROC_KCORE_TEXT=y
CONFIG_ILLEGAL_POINTER_VALUE=0xdead000000000000
CONFIG_X86_PMEM_LEGACY_DEVICE=y
CONFIG_X86_PMEM_LEGACY=y
CONFIG_X86_CHECK_BIOS_CORRUPTION=y
CONFIG_X86_BOOTPARAM_MEMORY_CORRUPTION_CHECK=y
CONFIG_MTRR=y
CONFIG_MTRR_SANITIZER=y
CONFIG_MTRR_SANITIZER_ENABLE_DEFAULT=0
CONFIG_MTRR_SANITIZER_SPARE_REG_NR_DEFAULT=1
CONFIG_X86_PAT=y
CONFIG_ARCH_USES_PG_UNCACHED=y
CONFIG_X86_UMIP=y
CONFIG_CC_HAS_IBT=y
CONFIG_X86_KERNEL_IBT=y
CONFIG_X86_INTEL_MEMORY_PROTECTION_KEYS=y
CONFIG_X86_INTEL_TSX_MODE_OFF=y
# CONFIG_X86_INTEL_TSX_MODE_ON is not set
# CONFIG_X86_INTEL_TSX_MODE_AUTO is not set
CONFIG_X86_SGX=y
CONFIG_EFI=y
CONFIG_EFI_STUB=y
CONFIG_EFI_MIXED=y
# CONFIG_HZ_100 is not set
CONFIG_HZ_250=y
# CONFIG_HZ_300 is not set
# CONFIG_HZ_1000 is not set
CONFIG_HZ=250
CONFIG_SCHED_HRTICK=y
CONFIG_KEXEC=y
CONFIG_KEXEC_FILE=y
CONFIG_ARCH_HAS_KEXEC_PURGATORY=y
CONFIG_KEXEC_SIG=y
CONFIG_KEXEC_SIG_FORCE=y
CONFIG_KEXEC_BZIMAGE_VERIFY_SIG=y
CONFIG_CRASH_DUMP=y
CONFIG_KEXEC_JUMP=y
CONFIG_PHYSICAL_START=0x1000000
CONFIG_RELOCATABLE=y
# CONFIG_RANDOMIZE_BASE is not set
CONFIG_PHYSICAL_ALIGN=0x200000
CONFIG_DYNAMIC_MEMORY_LAYOUT=y
CONFIG_HOTPLUG_CPU=y
CONFIG_BOOTPARAM_HOTPLUG_CPU0=y
CONFIG_DEBUG_HOTPLUG_CPU0=y
CONFIG_COMPAT_VDSO=y
CONFIG_LEGACY_VSYSCALL_XONLY=y
# CONFIG_LEGACY_VSYSCALL_NONE is not set
CONFIG_CMDLINE_BOOL=y
CONFIG_CMDLINE=""
CONFIG_MODIFY_LDT_SYSCALL=y
CONFIG_STRICT_SIGALTSTACK_SIZE=y
CONFIG_HAVE_LIVEPATCH=y
CONFIG_LIVEPATCH=y
# end of Processor type and features

CONFIG_CC_HAS_SLS=y
CONFIG_CC_HAS_RETURN_THUNK=y
CONFIG_SPECULATION_MITIGATIONS=y
CONFIG_PAGE_TABLE_ISOLATION=y
CONFIG_RETPOLINE=y
CONFIG_RETHUNK=y
CONFIG_CPU_UNRET_ENTRY=y
CONFIG_CPU_IBPB_ENTRY=y
CONFIG_CPU_IBRS_ENTRY=y
CONFIG_SLS=y
CONFIG_ARCH_HAS_ADD_PAGES=y
CONFIG_ARCH_MHP_MEMMAP_ON_MEMORY_ENABLE=y

#
# Power management and ACPI options
#
CONFIG_ARCH_HIBERNATION_HEADER=y
CONFIG_SUSPEND=y
CONFIG_SUSPEND_FREEZER=y
CONFIG_SUSPEND_SKIP_SYNC=y
CONFIG_HIBERNATE_CALLBACKS=y
CONFIG_HIBERNATION=y
CONFIG_HIBERNATION_SNAPSHOT_DEV=y
CONFIG_PM_STD_PARTITION=""
CONFIG_PM_SLEEP=y
CONFIG_PM_SLEEP_SMP=y
CONFIG_PM_AUTOSLEEP=y
CONFIG_PM_USERSPACE_AUTOSLEEP=y
CONFIG_PM_WAKELOCKS=y
CONFIG_PM_WAKELOCKS_LIMIT=100
CONFIG_PM_WAKELOCKS_GC=y
CONFIG_PM=y
CONFIG_PM_DEBUG=y
CONFIG_PM_ADVANCED_DEBUG=y
CONFIG_PM_TEST_SUSPEND=y
CONFIG_PM_SLEEP_DEBUG=y
CONFIG_DPM_WATCHDOG=y
CONFIG_DPM_WATCHDOG_TIMEOUT=120
CONFIG_PM_TRACE=y
CONFIG_PM_TRACE_RTC=y
CONFIG_PM_CLK=y
CONFIG_PM_GENERIC_DOMAINS=y
CONFIG_WQ_POWER_EFFICIENT_DEFAULT=y
CONFIG_PM_GENERIC_DOMAINS_SLEEP=y
CONFIG_PM_GENERIC_DOMAINS_OF=y
CONFIG_ENERGY_MODEL=y
CONFIG_ARCH_SUPPORTS_ACPI=y
CONFIG_ACPI=y
CONFIG_ACPI_LEGACY_TABLES_LOOKUP=y
CONFIG_ARCH_MIGHT_HAVE_ACPI_PDC=y
CONFIG_ACPI_SYSTEM_POWER_STATES_SUPPORT=y
CONFIG_ACPI_TABLE_LIB=y
CONFIG_ACPI_DEBUGGER=y
CONFIG_ACPI_DEBUGGER_USER=y
CONFIG_ACPI_SPCR_TABLE=y
CONFIG_ACPI_FPDT=y
CONFIG_ACPI_LPIT=y
CONFIG_ACPI_SLEEP=y
CONFIG_ACPI_REV_OVERRIDE_POSSIBLE=y
CONFIG_ACPI_EC_DEBUGFS=y
CONFIG_ACPI_AC=y
CONFIG_ACPI_BATTERY=y
CONFIG_ACPI_BUTTON=y
CONFIG_ACPI_VIDEO=y
CONFIG_ACPI_FAN=y
CONFIG_ACPI_TAD=y
CONFIG_ACPI_DOCK=y
CONFIG_ACPI_CPU_FREQ_PSS=y
CONFIG_ACPI_PROCESSOR_CSTATE=y
CONFIG_ACPI_PROCESSOR_IDLE=y
CONFIG_ACPI_CPPC_LIB=y
CONFIG_ACPI_PROCESSOR=y
CONFIG_ACPI_IPMI=y
CONFIG_ACPI_HOTPLUG_CPU=y
CONFIG_ACPI_PROCESSOR_AGGREGATOR=y
CONFIG_ACPI_THERMAL=y
CONFIG_ACPI_PLATFORM_PROFILE=y
CONFIG_ARCH_HAS_ACPI_TABLE_UPGRADE=y
CONFIG_ACPI_TABLE_UPGRADE=y
CONFIG_ACPI_DEBUG=y
CONFIG_ACPI_PCI_SLOT=y
CONFIG_ACPI_CONTAINER=y
CONFIG_ACPI_HOTPLUG_MEMORY=y
CONFIG_ACPI_HOTPLUG_IOAPIC=y
CONFIG_ACPI_SBS=y
CONFIG_ACPI_HED=y
CONFIG_ACPI_CUSTOM_METHOD=y
CONFIG_ACPI_BGRT=y
CONFIG_ACPI_REDUCED_HARDWARE_ONLY=y
CONFIG_ACPI_NFIT=y
CONFIG_NFIT_SECURITY_DEBUG=y
CONFIG_ACPI_NUMA=y
CONFIG_ACPI_HMAT=y
CONFIG_HAVE_ACPI_APEI=y
CONFIG_HAVE_ACPI_APEI_NMI=y
CONFIG_ACPI_APEI=y
CONFIG_ACPI_APEI_GHES=y
CONFIG_ACPI_APEI_PCIEAER=y
CONFIG_ACPI_APEI_MEMORY_FAILURE=y
CONFIG_ACPI_APEI_EINJ=y
CONFIG_ACPI_APEI_ERST_DEBUG=y
CONFIG_ACPI_DPTF=y
CONFIG_DPTF_POWER=y
CONFIG_DPTF_PCH_FIVR=y
CONFIG_ACPI_WATCHDOG=y
CONFIG_ACPI_EXTLOG=y
CONFIG_ACPI_ADXL=y
CONFIG_ACPI_CONFIGFS=y
CONFIG_ACPI_PFRUT=y
CONFIG_ACPI_PCC=y
CONFIG_PMIC_OPREGION=y
CONFIG_BYTCRC_PMIC_OPREGION=y
CONFIG_CHTCRC_PMIC_OPREGION=y
CONFIG_XPOWER_PMIC_OPREGION=y
CONFIG_BXT_WC_PMIC_OPREGION=y
CONFIG_CHT_WC_PMIC_OPREGION=y
CONFIG_CHT_DC_TI_PMIC_OPREGION=y
CONFIG_TPS68470_PMIC_OPREGION=y
CONFIG_ACPI_VIOT=y
CONFIG_ACPI_PRMT=y
CONFIG_X86_PM_TIMER=y

#
# CPU Frequency scaling
#
CONFIG_CPU_FREQ=y
CONFIG_CPU_FREQ_GOV_ATTR_SET=y
CONFIG_CPU_FREQ_GOV_COMMON=y
CONFIG_CPU_FREQ_STAT=y
# CONFIG_CPU_FREQ_DEFAULT_GOV_PERFORMANCE is not set
# CONFIG_CPU_FREQ_DEFAULT_GOV_POWERSAVE is not set
# CONFIG_CPU_FREQ_DEFAULT_GOV_USERSPACE is not set
CONFIG_CPU_FREQ_DEFAULT_GOV_SCHEDUTIL=y
CONFIG_CPU_FREQ_GOV_PERFORMANCE=y
CONFIG_CPU_FREQ_GOV_POWERSAVE=y
CONFIG_CPU_FREQ_GOV_USERSPACE=y
CONFIG_CPU_FREQ_GOV_ONDEMAND=y
CONFIG_CPU_FREQ_GOV_CONSERVATIVE=y
CONFIG_CPU_FREQ_GOV_SCHEDUTIL=y

#
# CPU frequency scaling drivers
#
CONFIG_CPUFREQ_DT=y
CONFIG_CPUFREQ_DT_PLATDEV=y
CONFIG_X86_INTEL_PSTATE=y
CONFIG_X86_PCC_CPUFREQ=y
CONFIG_X86_AMD_PSTATE=y
CONFIG_X86_ACPI_CPUFREQ=y
CONFIG_X86_ACPI_CPUFREQ_CPB=y
CONFIG_X86_POWERNOW_K8=y
CONFIG_X86_AMD_FREQ_SENSITIVITY=y
CONFIG_X86_SPEEDSTEP_CENTRINO=y
CONFIG_X86_P4_CLOCKMOD=y

#
# shared options
#
CONFIG_X86_SPEEDSTEP_LIB=y
# end of CPU Frequency scaling

#
# CPU Idle
#
CONFIG_CPU_IDLE=y
CONFIG_CPU_IDLE_GOV_LADDER=y
CONFIG_CPU_IDLE_GOV_MENU=y
CONFIG_CPU_IDLE_GOV_TEO=y
CONFIG_CPU_IDLE_GOV_HALTPOLL=y
CONFIG_HALTPOLL_CPUIDLE=y
# end of CPU Idle

CONFIG_INTEL_IDLE=y
# end of Power management and ACPI options

#
# Bus options (PCI etc.)
#
CONFIG_PCI_DIRECT=y
CONFIG_PCI_MMCONFIG=y
CONFIG_PCI_XEN=y
CONFIG_MMCONF_FAM10H=y
CONFIG_PCI_CNB20LE_QUIRK=y
CONFIG_ISA_BUS=y
CONFIG_ISA_DMA_API=y
CONFIG_AMD_NB=y
# end of Bus options (PCI etc.)

#
# Binary Emulations
#
CONFIG_IA32_EMULATION=y
CONFIG_X86_X32_ABI=y
CONFIG_COMPAT_32=y
CONFIG_COMPAT=y
CONFIG_COMPAT_FOR_U64_ALIGNMENT=y
# end of Binary Emulations

CONFIG_HAVE_KVM=y
CONFIG_HAVE_KVM_PFNCACHE=y
CONFIG_HAVE_KVM_IRQCHIP=y
CONFIG_HAVE_KVM_IRQFD=y
CONFIG_HAVE_KVM_IRQ_ROUTING=y
CONFIG_HAVE_KVM_DIRTY_RING=y
CONFIG_HAVE_KVM_EVENTFD=y
CONFIG_KVM_MMIO=y
CONFIG_KVM_ASYNC_PF=y
CONFIG_HAVE_KVM_MSI=y
CONFIG_HAVE_KVM_CPU_RELAX_INTERCEPT=y
CONFIG_KVM_VFIO=y
CONFIG_KVM_GENERIC_DIRTYLOG_READ_PROTECT=y
CONFIG_KVM_COMPAT=y
CONFIG_HAVE_KVM_IRQ_BYPASS=y
CONFIG_HAVE_KVM_NO_POLL=y
CONFIG_KVM_XFER_TO_GUEST_WORK=y
CONFIG_HAVE_KVM_PM_NOTIFIER=y
CONFIG_VIRTUALIZATION=y
CONFIG_KVM=y
# CONFIG_KVM_WERROR is not set
CONFIG_KVM_INTEL=y
CONFIG_X86_SGX_KVM=y
CONFIG_KVM_AMD=y
CONFIG_KVM_AMD_SEV=y
CONFIG_KVM_XEN=y
CONFIG_KVM_EXTERNAL_WRITE_TRACKING=y
CONFIG_AS_AVX512=y
CONFIG_AS_SHA1_NI=y
CONFIG_AS_SHA256_NI=y
CONFIG_AS_TPAUSE=y

#
# General architecture-dependent options
#
CONFIG_CRASH_CORE=y
CONFIG_KEXEC_CORE=y
CONFIG_HAVE_IMA_KEXEC=y
CONFIG_HOTPLUG_SMT=y
CONFIG_GENERIC_ENTRY=y
CONFIG_KPROBES=y
CONFIG_JUMP_LABEL=y
CONFIG_STATIC_KEYS_SELFTEST=y
CONFIG_STATIC_CALL_SELFTEST=y
CONFIG_OPTPROBES=y
CONFIG_KPROBES_ON_FTRACE=y
CONFIG_UPROBES=y
CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS=y
CONFIG_ARCH_USE_BUILTIN_BSWAP=y
CONFIG_KRETPROBES=y
CONFIG_KRETPROBE_ON_RETHOOK=y
CONFIG_USER_RETURN_NOTIFIER=y
CONFIG_HAVE_IOREMAP_PROT=y
CONFIG_HAVE_KPROBES=y
CONFIG_HAVE_KRETPROBES=y
CONFIG_HAVE_OPTPROBES=y
CONFIG_HAVE_KPROBES_ON_FTRACE=y
CONFIG_ARCH_CORRECT_STACKTRACE_ON_KRETPROBE=y
CONFIG_HAVE_FUNCTION_ERROR_INJECTION=y
CONFIG_HAVE_NMI=y
CONFIG_TRACE_IRQFLAGS_SUPPORT=y
CONFIG_TRACE_IRQFLAGS_NMI_SUPPORT=y
CONFIG_HAVE_ARCH_TRACEHOOK=y
CONFIG_HAVE_DMA_CONTIGUOUS=y
CONFIG_GENERIC_SMP_IDLE_THREAD=y
CONFIG_ARCH_HAS_FORTIFY_SOURCE=y
CONFIG_ARCH_HAS_SET_MEMORY=y
CONFIG_ARCH_HAS_SET_DIRECT_MAP=y
CONFIG_HAVE_ARCH_THREAD_STRUCT_WHITELIST=y
CONFIG_ARCH_WANTS_DYNAMIC_TASK_STRUCT=y
CONFIG_ARCH_WANTS_NO_INSTR=y
CONFIG_HAVE_ASM_MODVERSIONS=y
CONFIG_HAVE_REGS_AND_STACK_ACCESS_API=y
CONFIG_HAVE_RSEQ=y
CONFIG_HAVE_FUNCTION_ARG_ACCESS_API=y
CONFIG_HAVE_HW_BREAKPOINT=y
CONFIG_HAVE_MIXED_BREAKPOINTS_REGS=y
CONFIG_HAVE_USER_RETURN_NOTIFIER=y
CONFIG_HAVE_PERF_EVENTS_NMI=y
CONFIG_HAVE_HARDLOCKUP_DETECTOR_PERF=y
CONFIG_HAVE_PERF_REGS=y
CONFIG_HAVE_PERF_USER_STACK_DUMP=y
CONFIG_HAVE_ARCH_JUMP_LABEL=y
CONFIG_HAVE_ARCH_JUMP_LABEL_RELATIVE=y
CONFIG_MMU_GATHER_TABLE_FREE=y
CONFIG_MMU_GATHER_RCU_TABLE_FREE=y
CONFIG_MMU_GATHER_MERGE_VMAS=y
CONFIG_ARCH_HAVE_NMI_SAFE_CMPXCHG=y
CONFIG_HAVE_ALIGNED_STRUCT_PAGE=y
CONFIG_HAVE_CMPXCHG_LOCAL=y
CONFIG_HAVE_CMPXCHG_DOUBLE=y
CONFIG_ARCH_WANT_COMPAT_IPC_PARSE_VERSION=y
CONFIG_ARCH_WANT_OLD_COMPAT_IPC=y
CONFIG_HAVE_ARCH_SECCOMP=y
CONFIG_HAVE_ARCH_SECCOMP_FILTER=y
CONFIG_SECCOMP=y
CONFIG_SECCOMP_FILTER=y
CONFIG_SECCOMP_CACHE_DEBUG=y
CONFIG_HAVE_ARCH_STACKLEAK=y
CONFIG_HAVE_STACKPROTECTOR=y
CONFIG_STACKPROTECTOR=y
CONFIG_STACKPROTECTOR_STRONG=y
CONFIG_ARCH_SUPPORTS_LTO_CLANG=y
CONFIG_ARCH_SUPPORTS_LTO_CLANG_THIN=y
CONFIG_LTO_NONE=y
CONFIG_HAVE_ARCH_WITHIN_STACK_FRAMES=y
CONFIG_HAVE_CONTEXT_TRACKING_USER=y
CONFIG_HAVE_CONTEXT_TRACKING_USER_OFFSTACK=y
CONFIG_HAVE_VIRT_CPU_ACCOUNTING_GEN=y
CONFIG_HAVE_IRQ_TIME_ACCOUNTING=y
CONFIG_HAVE_MOVE_PUD=y
CONFIG_HAVE_MOVE_PMD=y
CONFIG_HAVE_ARCH_TRANSPARENT_HUGEPAGE=y
CONFIG_HAVE_ARCH_TRANSPARENT_HUGEPAGE_PUD=y
CONFIG_HAVE_ARCH_HUGE_VMAP=y
CONFIG_HAVE_ARCH_HUGE_VMALLOC=y
CONFIG_ARCH_WANT_HUGE_PMD_SHARE=y
CONFIG_HAVE_ARCH_SOFT_DIRTY=y
CONFIG_HAVE_MOD_ARCH_SPECIFIC=y
CONFIG_MODULES_USE_ELF_RELA=y
CONFIG_HAVE_IRQ_EXIT_ON_IRQ_STACK=y
CONFIG_HAVE_SOFTIRQ_ON_OWN_STACK=y
CONFIG_ARCH_HAS_ELF_RANDOMIZE=y
CONFIG_HAVE_ARCH_MMAP_RND_BITS=y
CONFIG_HAVE_EXIT_THREAD=y
CONFIG_ARCH_MMAP_RND_BITS=28
CONFIG_HAVE_ARCH_MMAP_RND_COMPAT_BITS=y
CONFIG_ARCH_MMAP_RND_COMPAT_BITS=8
CONFIG_HAVE_ARCH_COMPAT_MMAP_BASES=y
CONFIG_PAGE_SIZE_LESS_THAN_64KB=y
CONFIG_PAGE_SIZE_LESS_THAN_256KB=y
CONFIG_HAVE_OBJTOOL=y
CONFIG_HAVE_JUMP_LABEL_HACK=y
CONFIG_HAVE_NOINSTR_HACK=y
CONFIG_HAVE_NOINSTR_VALIDATION=y
CONFIG_HAVE_UACCESS_VALIDATION=y
CONFIG_HAVE_STACK_VALIDATION=y
CONFIG_HAVE_RELIABLE_STACKTRACE=y
CONFIG_ISA_BUS_API=y
CONFIG_OLD_SIGSUSPEND3=y
CONFIG_COMPAT_OLD_SIGACTION=y
CONFIG_COMPAT_32BIT_TIME=y
CONFIG_HAVE_ARCH_VMAP_STACK=y
CONFIG_VMAP_STACK=y
CONFIG_HAVE_ARCH_RANDOMIZE_KSTACK_OFFSET=y
CONFIG_RANDOMIZE_KSTACK_OFFSET=y
CONFIG_RANDOMIZE_KSTACK_OFFSET_DEFAULT=y
CONFIG_ARCH_HAS_STRICT_KERNEL_RWX=y
CONFIG_STRICT_KERNEL_RWX=y
CONFIG_ARCH_HAS_STRICT_MODULE_RWX=y
CONFIG_STRICT_MODULE_RWX=y
CONFIG_HAVE_ARCH_PREL32_RELOCATIONS=y
CONFIG_ARCH_USE_MEMREMAP_PROT=y
CONFIG_LOCK_EVENT_COUNTS=y
CONFIG_ARCH_HAS_MEM_ENCRYPT=y
CONFIG_ARCH_HAS_CC_PLATFORM=y
CONFIG_HAVE_STATIC_CALL=y
CONFIG_HAVE_STATIC_CALL_INLINE=y
CONFIG_HAVE_PREEMPT_DYNAMIC=y
CONFIG_HAVE_PREEMPT_DYNAMIC_CALL=y
CONFIG_ARCH_WANT_LD_ORPHAN_WARN=y
CONFIG_ARCH_SUPPORTS_DEBUG_PAGEALLOC=y
CONFIG_ARCH_SUPPORTS_PAGE_TABLE_CHECK=y
CONFIG_ARCH_HAS_ELFCORE_COMPAT=y
CONFIG_ARCH_HAS_PARANOID_L1D_FLUSH=y
CONFIG_DYNAMIC_SIGFRAME=y
CONFIG_HAVE_ARCH_NODE_DEV_GROUP=y
CONFIG_ARCH_HAS_NONLEAF_PMD_YOUNG=y

#
# GCOV-based kernel profiling
#
CONFIG_GCOV_KERNEL=y
CONFIG_ARCH_HAS_GCOV_PROFILE_ALL=y
# CONFIG_GCOV_PROFILE_ALL is not set
# end of GCOV-based kernel profiling

CONFIG_HAVE_GCC_PLUGINS=y
CONFIG_GCC_PLUGINS=y
CONFIG_GCC_PLUGIN_LATENT_ENTROPY=y
# end of General architecture-dependent options

CONFIG_RT_MUTEXES=y
CONFIG_BASE_SMALL=0
CONFIG_MODULE_SIG_FORMAT=y
CONFIG_MODULES=y
CONFIG_MODULE_FORCE_LOAD=y
CONFIG_MODULE_UNLOAD=y
CONFIG_MODULE_FORCE_UNLOAD=y
CONFIG_MODULE_UNLOAD_TAINT_TRACKING=y
CONFIG_MODVERSIONS=y
CONFIG_ASM_MODVERSIONS=y
CONFIG_MODULE_SRCVERSION_ALL=y
CONFIG_MODULE_SIG=y
CONFIG_MODULE_SIG_FORCE=y
CONFIG_MODULE_SIG_ALL=y
CONFIG_MODULE_SIG_SHA1=y
# CONFIG_MODULE_SIG_SHA224 is not set
# CONFIG_MODULE_SIG_SHA256 is not set
# CONFIG_MODULE_SIG_SHA384 is not set
# CONFIG_MODULE_SIG_SHA512 is not set
CONFIG_MODULE_SIG_HASH="sha1"
CONFIG_MODULE_COMPRESS_NONE=y
# CONFIG_MODULE_COMPRESS_GZIP is not set
# CONFIG_MODULE_COMPRESS_XZ is not set
# CONFIG_MODULE_COMPRESS_ZSTD is not set
CONFIG_MODULE_ALLOW_MISSING_NAMESPACE_IMPORTS=y
CONFIG_MODPROBE_PATH="/sbin/modprobe"
# CONFIG_TRIM_UNUSED_KSYMS is not set
CONFIG_MODULES_TREE_LOOKUP=y
CONFIG_BLOCK=y
CONFIG_BLOCK_LEGACY_AUTOLOAD=y
CONFIG_BLK_RQ_ALLOC_TIME=y
CONFIG_BLK_CGROUP_RWSTAT=y
CONFIG_BLK_DEV_BSG_COMMON=y
CONFIG_BLK_ICQ=y
CONFIG_BLK_USE_PIN_USER_PAGES_FOR_DIO=y
CONFIG_BLK_DEV_BSGLIB=y
CONFIG_BLK_DEV_INTEGRITY=y
CONFIG_BLK_DEV_INTEGRITY_T10=y
CONFIG_BLK_DEV_ZONED=y
CONFIG_BLK_DEV_THROTTLING=y
CONFIG_BLK_DEV_THROTTLING_LOW=y
CONFIG_BLK_WBT=y
CONFIG_BLK_WBT_MQ=y
CONFIG_BLK_CGROUP_IOLATENCY=y
CONFIG_BLK_CGROUP_FC_APPID=y
CONFIG_BLK_CGROUP_IOCOST=y
CONFIG_BLK_CGROUP_IOPRIO=y
CONFIG_BLK_DEBUG_FS=y
CONFIG_BLK_DEBUG_FS_ZONED=y
CONFIG_BLK_SED_OPAL=y
CONFIG_BLK_INLINE_ENCRYPTION=y
CONFIG_BLK_INLINE_ENCRYPTION_FALLBACK=y

#
# Partition Types
#
CONFIG_PARTITION_ADVANCED=y
CONFIG_ACORN_PARTITION=y
CONFIG_ACORN_PARTITION_CUMANA=y
CONFIG_ACORN_PARTITION_EESOX=y
CONFIG_ACORN_PARTITION_ICS=y
CONFIG_ACORN_PARTITION_ADFS=y
CONFIG_ACORN_PARTITION_POWERTEC=y
CONFIG_ACORN_PARTITION_RISCIX=y
CONFIG_AIX_PARTITION=y
CONFIG_OSF_PARTITION=y
CONFIG_AMIGA_PARTITION=y
CONFIG_ATARI_PARTITION=y
CONFIG_MAC_PARTITION=y
CONFIG_MSDOS_PARTITION=y
CONFIG_BSD_DISKLABEL=y
CONFIG_MINIX_SUBPARTITION=y
CONFIG_SOLARIS_X86_PARTITION=y
CONFIG_UNIXWARE_DISKLABEL=y
CONFIG_LDM_PARTITION=y
CONFIG_LDM_DEBUG=y
CONFIG_SGI_PARTITION=y
CONFIG_ULTRIX_PARTITION=y
CONFIG_SUN_PARTITION=y
CONFIG_KARMA_PARTITION=y
CONFIG_EFI_PARTITION=y
CONFIG_SYSV68_PARTITION=y
CONFIG_CMDLINE_PARTITION=y
# end of Partition Types

CONFIG_BLOCK_COMPAT=y
CONFIG_BLK_MQ_PCI=y
CONFIG_BLK_MQ_VIRTIO=y
CONFIG_BLK_MQ_RDMA=y
CONFIG_BLK_PM=y
CONFIG_BLOCK_HOLDER_DEPRECATED=y
CONFIG_BLK_MQ_STACKING=y

#
# IO Schedulers
#
CONFIG_MQ_IOSCHED_DEADLINE=y
CONFIG_MQ_IOSCHED_KYBER=y
CONFIG_IOSCHED_BFQ=y
CONFIG_BFQ_GROUP_IOSCHED=y
CONFIG_BFQ_CGROUP_DEBUG=y
# end of IO Schedulers

CONFIG_PREEMPT_NOTIFIERS=y
CONFIG_PADATA=y
CONFIG_ASN1=y
CONFIG_UNINLINE_SPIN_UNLOCK=y
CONFIG_ARCH_SUPPORTS_ATOMIC_RMW=y
CONFIG_MUTEX_SPIN_ON_OWNER=y
CONFIG_RWSEM_SPIN_ON_OWNER=y
CONFIG_LOCK_SPIN_ON_OWNER=y
CONFIG_ARCH_USE_QUEUED_SPINLOCKS=y
CONFIG_QUEUED_SPINLOCKS=y
CONFIG_ARCH_USE_QUEUED_RWLOCKS=y
CONFIG_QUEUED_RWLOCKS=y
CONFIG_ARCH_HAS_NON_OVERLAPPING_ADDRESS_SPACE=y
CONFIG_ARCH_HAS_SYNC_CORE_BEFORE_USERMODE=y
CONFIG_ARCH_HAS_SYSCALL_WRAPPER=y
CONFIG_FREEZER=y

#
# Executable file formats
#
CONFIG_BINFMT_ELF=y
CONFIG_BINFMT_ELF_KUNIT_TEST=y
CONFIG_COMPAT_BINFMT_ELF=y
CONFIG_ELFCORE=y
CONFIG_CORE_DUMP_DEFAULT_ELF_HEADERS=y
CONFIG_BINFMT_SCRIPT=y
CONFIG_BINFMT_MISC=y
CONFIG_COREDUMP=y
# end of Executable file formats

#
# Memory Management options
#
CONFIG_ZPOOL=y
CONFIG_SWAP=y
CONFIG_ZSWAP=y
CONFIG_ZSWAP_DEFAULT_ON=y
# CONFIG_ZSWAP_COMPRESSOR_DEFAULT_DEFLATE is not set
CONFIG_ZSWAP_COMPRESSOR_DEFAULT_LZO=y
# CONFIG_ZSWAP_COMPRESSOR_DEFAULT_842 is not set
# CONFIG_ZSWAP_COMPRESSOR_DEFAULT_LZ4 is not set
# CONFIG_ZSWAP_COMPRESSOR_DEFAULT_LZ4HC is not set
# CONFIG_ZSWAP_COMPRESSOR_DEFAULT_ZSTD is not set
CONFIG_ZSWAP_COMPRESSOR_DEFAULT="lzo"
CONFIG_ZSWAP_ZPOOL_DEFAULT_ZBUD=y
# CONFIG_ZSWAP_ZPOOL_DEFAULT_Z3FOLD is not set
# CONFIG_ZSWAP_ZPOOL_DEFAULT_ZSMALLOC is not set
CONFIG_ZSWAP_ZPOOL_DEFAULT="zbud"
CONFIG_ZBUD=y
CONFIG_Z3FOLD=y
CONFIG_ZSMALLOC=y
CONFIG_ZSMALLOC_STAT=y

#
# SLAB allocator options
#
# CONFIG_SLAB is not set
CONFIG_SLUB=y
# CONFIG_SLOB is not set
CONFIG_SLAB_MERGE_DEFAULT=y
CONFIG_SLAB_FREELIST_RANDOM=y
CONFIG_SLAB_FREELIST_HARDENED=y
CONFIG_SLUB_STATS=y
CONFIG_SLUB_CPU_PARTIAL=y
# end of SLAB allocator options

CONFIG_SHUFFLE_PAGE_ALLOCATOR=y
CONFIG_COMPAT_BRK=y
CONFIG_SPARSEMEM=y
CONFIG_SPARSEMEM_EXTREME=y
CONFIG_SPARSEMEM_VMEMMAP_ENABLE=y
CONFIG_SPARSEMEM_VMEMMAP=y
CONFIG_HAVE_FAST_GUP=y
CONFIG_NUMA_KEEP_MEMINFO=y
CONFIG_MEMORY_ISOLATION=y
CONFIG_EXCLUSIVE_SYSTEM_RAM=y
CONFIG_HAVE_BOOTMEM_INFO_NODE=y
CONFIG_ARCH_ENABLE_MEMORY_HOTPLUG=y
CONFIG_ARCH_ENABLE_MEMORY_HOTREMOVE=y
CONFIG_MEMORY_HOTPLUG=y
CONFIG_MEMORY_HOTPLUG_DEFAULT_ONLINE=y
CONFIG_MEMORY_HOTREMOVE=y
CONFIG_MHP_MEMMAP_ON_MEMORY=y
CONFIG_SPLIT_PTLOCK_CPUS=4
CONFIG_ARCH_ENABLE_SPLIT_PMD_PTLOCK=y
CONFIG_MEMORY_BALLOON=y
CONFIG_BALLOON_COMPACTION=y
CONFIG_COMPACTION=y
CONFIG_PAGE_REPORTING=y
CONFIG_MIGRATION=y
CONFIG_DEVICE_MIGRATION=y
CONFIG_ARCH_ENABLE_HUGEPAGE_MIGRATION=y
CONFIG_ARCH_ENABLE_THP_MIGRATION=y
CONFIG_CONTIG_ALLOC=y
CONFIG_PHYS_ADDR_T_64BIT=y
CONFIG_MMU_NOTIFIER=y
CONFIG_KSM=y
CONFIG_DEFAULT_MMAP_MIN_ADDR=4096
CONFIG_ARCH_SUPPORTS_MEMORY_FAILURE=y
CONFIG_MEMORY_FAILURE=y
CONFIG_HWPOISON_INJECT=y
CONFIG_ARCH_WANT_GENERAL_HUGETLB=y
CONFIG_ARCH_WANTS_THP_SWAP=y
CONFIG_TRANSPARENT_HUGEPAGE=y
CONFIG_TRANSPARENT_HUGEPAGE_ALWAYS=y
# CONFIG_TRANSPARENT_HUGEPAGE_MADVISE is not set
CONFIG_THP_SWAP=y
CONFIG_READ_ONLY_THP_FOR_FS=y
CONFIG_NEED_PER_CPU_EMBED_FIRST_CHUNK=y
CONFIG_NEED_PER_CPU_PAGE_FIRST_CHUNK=y
CONFIG_USE_PERCPU_NUMA_NODE_ID=y
CONFIG_HAVE_SETUP_PER_CPU_AREA=y
CONFIG_FRONTSWAP=y
CONFIG_CMA=y
CONFIG_CMA_DEBUG=y
CONFIG_CMA_DEBUGFS=y
CONFIG_CMA_SYSFS=y
CONFIG_CMA_AREAS=19
CONFIG_MEM_SOFT_DIRTY=y
CONFIG_GENERIC_EARLY_IOREMAP=y
CONFIG_DEFERRED_STRUCT_PAGE_INIT=y
CONFIG_PAGE_IDLE_FLAG=y
CONFIG_IDLE_PAGE_TRACKING=y
CONFIG_ARCH_HAS_CACHE_LINE_SIZE=y
CONFIG_ARCH_HAS_CURRENT_STACK_POINTER=y
CONFIG_ARCH_HAS_PTE_DEVMAP=y
CONFIG_ARCH_HAS_ZONE_DMA_SET=y
CONFIG_ZONE_DMA=y
CONFIG_ZONE_DMA32=y
CONFIG_ZONE_DEVICE=y
CONFIG_HMM_MIRROR=y
CONFIG_GET_FREE_REGION=y
CONFIG_DEVICE_PRIVATE=y
CONFIG_VMAP_PFN=y
CONFIG_ARCH_USES_HIGH_VMA_FLAGS=y
CONFIG_ARCH_HAS_PKEYS=y
CONFIG_VM_EVENT_COUNTERS=y
CONFIG_PERCPU_STATS=y
CONFIG_GUP_TEST=y
CONFIG_ARCH_HAS_PTE_SPECIAL=y
CONFIG_MAPPING_DIRTY_HELPERS=y
CONFIG_ANON_VMA_NAME=y
CONFIG_USERFAULTFD=y
CONFIG_HAVE_ARCH_USERFAULTFD_WP=y
CONFIG_HAVE_ARCH_USERFAULTFD_MINOR=y
CONFIG_PTE_MARKER=y
CONFIG_PTE_MARKER_UFFD_WP=y
CONFIG_LRU_GEN=y
CONFIG_LRU_GEN_ENABLED=y
CONFIG_LRU_GEN_STATS=y

#
# Data Access Monitoring
#
CONFIG_DAMON=y
CONFIG_DAMON_KUNIT_TEST=y
CONFIG_DAMON_VADDR=y
CONFIG_DAMON_PADDR=y
CONFIG_DAMON_VADDR_KUNIT_TEST=y
CONFIG_DAMON_SYSFS=y
CONFIG_DAMON_DBGFS=y
CONFIG_DAMON_DBGFS_KUNIT_TEST=y
CONFIG_DAMON_RECLAIM=y
CONFIG_DAMON_LRU_SORT=y
# end of Data Access Monitoring
# end of Memory Management options

CONFIG_NET=y
CONFIG_WANT_COMPAT_NETLINK_MESSAGES=y
CONFIG_COMPAT_NETLINK_MESSAGES=y
CONFIG_NET_INGRESS=y
CONFIG_NET_EGRESS=y
CONFIG_NET_REDIRECT=y
CONFIG_SKB_EXTENSIONS=y

#
# Networking options
#
CONFIG_PACKET=y
CONFIG_PACKET_DIAG=y
CONFIG_UNIX=y
CONFIG_UNIX_SCM=y
CONFIG_AF_UNIX_OOB=y
CONFIG_UNIX_DIAG=y
CONFIG_TLS=y
CONFIG_TLS_DEVICE=y
CONFIG_TLS_TOE=y
CONFIG_XFRM=y
CONFIG_XFRM_OFFLOAD=y
CONFIG_XFRM_ALGO=y
CONFIG_XFRM_USER=y
CONFIG_XFRM_USER_COMPAT=y
CONFIG_XFRM_INTERFACE=y
CONFIG_XFRM_SUB_POLICY=y
CONFIG_XFRM_MIGRATE=y
CONFIG_XFRM_STATISTICS=y
CONFIG_XFRM_AH=y
CONFIG_XFRM_ESP=y
CONFIG_XFRM_IPCOMP=y
CONFIG_NET_KEY=y
CONFIG_NET_KEY_MIGRATE=y
CONFIG_XFRM_ESPINTCP=y
CONFIG_SMC=y
CONFIG_SMC_DIAG=y
CONFIG_XDP_SOCKETS=y
CONFIG_XDP_SOCKETS_DIAG=y
CONFIG_INET=y
CONFIG_IP_MULTICAST=y
CONFIG_IP_ADVANCED_ROUTER=y
CONFIG_IP_FIB_TRIE_STATS=y
CONFIG_IP_MULTIPLE_TABLES=y
CONFIG_IP_ROUTE_MULTIPATH=y
CONFIG_IP_ROUTE_VERBOSE=y
CONFIG_IP_ROUTE_CLASSID=y
CONFIG_IP_PNP=y
CONFIG_IP_PNP_DHCP=y
CONFIG_IP_PNP_BOOTP=y
CONFIG_IP_PNP_RARP=y
CONFIG_NET_IPIP=y
CONFIG_NET_IPGRE_DEMUX=y
CONFIG_NET_IP_TUNNEL=y
CONFIG_NET_IPGRE=y
CONFIG_NET_IPGRE_BROADCAST=y
CONFIG_IP_MROUTE_COMMON=y
CONFIG_IP_MROUTE=y
CONFIG_IP_MROUTE_MULTIPLE_TABLES=y
CONFIG_IP_PIMSM_V1=y
CONFIG_IP_PIMSM_V2=y
CONFIG_SYN_COOKIES=y
CONFIG_NET_IPVTI=y
CONFIG_NET_UDP_TUNNEL=y
CONFIG_NET_FOU=y
CONFIG_NET_FOU_IP_TUNNELS=y
CONFIG_INET_AH=y
CONFIG_INET_ESP=y
CONFIG_INET_ESP_OFFLOAD=y
CONFIG_INET_ESPINTCP=y
CONFIG_INET_IPCOMP=y
CONFIG_INET_XFRM_TUNNEL=y
CONFIG_INET_TUNNEL=y
CONFIG_INET_DIAG=y
CONFIG_INET_TCP_DIAG=y
CONFIG_INET_UDP_DIAG=y
CONFIG_INET_RAW_DIAG=y
CONFIG_INET_DIAG_DESTROY=y
CONFIG_TCP_CONG_ADVANCED=y
CONFIG_TCP_CONG_BIC=y
CONFIG_TCP_CONG_CUBIC=y
CONFIG_TCP_CONG_WESTWOOD=y
CONFIG_TCP_CONG_HTCP=y
CONFIG_TCP_CONG_HSTCP=y
CONFIG_TCP_CONG_HYBLA=y
CONFIG_TCP_CONG_VEGAS=y
CONFIG_TCP_CONG_NV=y
CONFIG_TCP_CONG_SCALABLE=y
CONFIG_TCP_CONG_LP=y
CONFIG_TCP_CONG_VENO=y
CONFIG_TCP_CONG_YEAH=y
CONFIG_TCP_CONG_ILLINOIS=y
CONFIG_TCP_CONG_DCTCP=y
CONFIG_TCP_CONG_CDG=y
CONFIG_TCP_CONG_BBR=y
# CONFIG_DEFAULT_BIC is not set
CONFIG_DEFAULT_CUBIC=y
# CONFIG_DEFAULT_HTCP is not set
# CONFIG_DEFAULT_HYBLA is not set
# CONFIG_DEFAULT_VEGAS is not set
# CONFIG_DEFAULT_VENO is not set
# CONFIG_DEFAULT_WESTWOOD is not set
# CONFIG_DEFAULT_DCTCP is not set
# CONFIG_DEFAULT_CDG is not set
# CONFIG_DEFAULT_BBR is not set
# CONFIG_DEFAULT_RENO is not set
CONFIG_DEFAULT_TCP_CONG="cubic"
CONFIG_TCP_MD5SIG=y
CONFIG_IPV6=y
CONFIG_IPV6_ROUTER_PREF=y
CONFIG_IPV6_ROUTE_INFO=y
CONFIG_IPV6_OPTIMISTIC_DAD=y
CONFIG_INET6_AH=y
CONFIG_INET6_ESP=y
CONFIG_INET6_ESP_OFFLOAD=y
CONFIG_INET6_ESPINTCP=y
CONFIG_INET6_IPCOMP=y
CONFIG_IPV6_MIP6=y
CONFIG_IPV6_ILA=y
CONFIG_INET6_XFRM_TUNNEL=y
CONFIG_INET6_TUNNEL=y
CONFIG_IPV6_VTI=y
CONFIG_IPV6_SIT=y
CONFIG_IPV6_SIT_6RD=y
CONFIG_IPV6_NDISC_NODETYPE=y
CONFIG_IPV6_TUNNEL=y
CONFIG_IPV6_GRE=y
CONFIG_IPV6_FOU=y
CONFIG_IPV6_FOU_TUNNEL=y
CONFIG_IPV6_MULTIPLE_TABLES=y
CONFIG_IPV6_SUBTREES=y
CONFIG_IPV6_MROUTE=y
CONFIG_IPV6_MROUTE_MULTIPLE_TABLES=y
CONFIG_IPV6_PIMSM_V2=y
CONFIG_IPV6_SEG6_LWTUNNEL=y
CONFIG_IPV6_SEG6_HMAC=y
CONFIG_IPV6_SEG6_BPF=y
CONFIG_IPV6_RPL_LWTUNNEL=y
CONFIG_IPV6_IOAM6_LWTUNNEL=y
CONFIG_NETLABEL=y
CONFIG_MPTCP=y
CONFIG_INET_MPTCP_DIAG=y
CONFIG_MPTCP_IPV6=y
CONFIG_MPTCP_KUNIT_TEST=y
CONFIG_NETWORK_SECMARK=y
CONFIG_NET_PTP_CLASSIFY=y
CONFIG_NETWORK_PHY_TIMESTAMPING=y
CONFIG_NETFILTER=y
CONFIG_NETFILTER_ADVANCED=y
CONFIG_BRIDGE_NETFILTER=y

#
# Core Netfilter Configuration
#
CONFIG_NETFILTER_INGRESS=y
CONFIG_NETFILTER_EGRESS=y
CONFIG_NETFILTER_SKIP_EGRESS=y
CONFIG_NETFILTER_NETLINK=y
CONFIG_NETFILTER_FAMILY_BRIDGE=y
CONFIG_NETFILTER_FAMILY_ARP=y
CONFIG_NETFILTER_NETLINK_HOOK=y
CONFIG_NETFILTER_NETLINK_ACCT=y
CONFIG_NETFILTER_NETLINK_QUEUE=y
CONFIG_NETFILTER_NETLINK_LOG=y
CONFIG_NETFILTER_NETLINK_OSF=y
CONFIG_NF_CONNTRACK=y
CONFIG_NF_LOG_SYSLOG=y
CONFIG_NETFILTER_CONNCOUNT=y
CONFIG_NF_CONNTRACK_MARK=y
CONFIG_NF_CONNTRACK_SECMARK=y
CONFIG_NF_CONNTRACK_ZONES=y
CONFIG_NF_CONNTRACK_PROCFS=y
CONFIG_NF_CONNTRACK_EVENTS=y
CONFIG_NF_CONNTRACK_TIMEOUT=y
CONFIG_NF_CONNTRACK_TIMESTAMP=y
CONFIG_NF_CONNTRACK_LABELS=y
CONFIG_NF_CT_PROTO_DCCP=y
CONFIG_NF_CT_PROTO_GRE=y
CONFIG_NF_CT_PROTO_SCTP=y
CONFIG_NF_CT_PROTO_UDPLITE=y
CONFIG_NF_CONNTRACK_AMANDA=y
CONFIG_NF_CONNTRACK_FTP=y
CONFIG_NF_CONNTRACK_H323=y
CONFIG_NF_CONNTRACK_IRC=y
CONFIG_NF_CONNTRACK_BROADCAST=y
CONFIG_NF_CONNTRACK_NETBIOS_NS=y
CONFIG_NF_CONNTRACK_SNMP=y
CONFIG_NF_CONNTRACK_PPTP=y
CONFIG_NF_CONNTRACK_SANE=y
CONFIG_NF_CONNTRACK_SIP=y
CONFIG_NF_CONNTRACK_TFTP=y
CONFIG_NF_CT_NETLINK=y
CONFIG_NF_CT_NETLINK_TIMEOUT=y
CONFIG_NF_CT_NETLINK_HELPER=y
CONFIG_NETFILTER_NETLINK_GLUE_CT=y
CONFIG_NF_NAT=y
CONFIG_NF_NAT_AMANDA=y
CONFIG_NF_NAT_FTP=y
CONFIG_NF_NAT_IRC=y
CONFIG_NF_NAT_SIP=y
CONFIG_NF_NAT_TFTP=y
CONFIG_NF_NAT_REDIRECT=y
CONFIG_NF_NAT_MASQUERADE=y
CONFIG_NETFILTER_SYNPROXY=y
CONFIG_NF_TABLES=y
CONFIG_NF_TABLES_INET=y
CONFIG_NF_TABLES_NETDEV=y
CONFIG_NFT_NUMGEN=y
CONFIG_NFT_CT=y
CONFIG_NFT_FLOW_OFFLOAD=y
CONFIG_NFT_CONNLIMIT=y
CONFIG_NFT_LOG=y
CONFIG_NFT_LIMIT=y
CONFIG_NFT_MASQ=y
CONFIG_NFT_REDIR=y
CONFIG_NFT_NAT=y
CONFIG_NFT_TUNNEL=y
CONFIG_NFT_OBJREF=y
CONFIG_NFT_QUEUE=y
CONFIG_NFT_QUOTA=y
CONFIG_NFT_REJECT=y
CONFIG_NFT_REJECT_INET=y
CONFIG_NFT_COMPAT=y
CONFIG_NFT_HASH=y
CONFIG_NFT_FIB=y
CONFIG_NFT_FIB_INET=y
CONFIG_NFT_XFRM=y
CONFIG_NFT_SOCKET=y
CONFIG_NFT_OSF=y
CONFIG_NFT_TPROXY=y
CONFIG_NFT_SYNPROXY=y
CONFIG_NF_DUP_NETDEV=y
CONFIG_NFT_DUP_NETDEV=y
CONFIG_NFT_FWD_NETDEV=y
CONFIG_NFT_FIB_NETDEV=y
CONFIG_NFT_REJECT_NETDEV=y
CONFIG_NF_FLOW_TABLE_INET=y
CONFIG_NF_FLOW_TABLE=y
CONFIG_NF_FLOW_TABLE_PROCFS=y
CONFIG_NETFILTER_XTABLES=y
CONFIG_NETFILTER_XTABLES_COMPAT=y

#
# Xtables combined modules
#
CONFIG_NETFILTER_XT_MARK=y
CONFIG_NETFILTER_XT_CONNMARK=y
CONFIG_NETFILTER_XT_SET=y

#
# Xtables targets
#
CONFIG_NETFILTER_XT_TARGET_AUDIT=y
CONFIG_NETFILTER_XT_TARGET_CHECKSUM=y
CONFIG_NETFILTER_XT_TARGET_CLASSIFY=y
CONFIG_NETFILTER_XT_TARGET_CONNMARK=y
CONFIG_NETFILTER_XT_TARGET_CONNSECMARK=y
CONFIG_NETFILTER_XT_TARGET_CT=y
CONFIG_NETFILTER_XT_TARGET_DSCP=y
CONFIG_NETFILTER_XT_TARGET_HL=y
CONFIG_NETFILTER_XT_TARGET_HMARK=y
CONFIG_NETFILTER_XT_TARGET_IDLETIMER=y
CONFIG_NETFILTER_XT_TARGET_LED=y
CONFIG_NETFILTER_XT_TARGET_LOG=y
CONFIG_NETFILTER_XT_TARGET_MARK=y
CONFIG_NETFILTER_XT_NAT=y
CONFIG_NETFILTER_XT_TARGET_NETMAP=y
CONFIG_NETFILTER_XT_TARGET_NFLOG=y
CONFIG_NETFILTER_XT_TARGET_NFQUEUE=y
CONFIG_NETFILTER_XT_TARGET_NOTRACK=y
CONFIG_NETFILTER_XT_TARGET_RATEEST=y
CONFIG_NETFILTER_XT_TARGET_REDIRECT=y
CONFIG_NETFILTER_XT_TARGET_MASQUERADE=y
CONFIG_NETFILTER_XT_TARGET_TEE=y
CONFIG_NETFILTER_XT_TARGET_TPROXY=y
CONFIG_NETFILTER_XT_TARGET_TRACE=y
CONFIG_NETFILTER_XT_TARGET_SECMARK=y
CONFIG_NETFILTER_XT_TARGET_TCPMSS=y
CONFIG_NETFILTER_XT_TARGET_TCPOPTSTRIP=y

#
# Xtables matches
#
CONFIG_NETFILTER_XT_MATCH_ADDRTYPE=y
CONFIG_NETFILTER_XT_MATCH_BPF=y
CONFIG_NETFILTER_XT_MATCH_CGROUP=y
CONFIG_NETFILTER_XT_MATCH_CLUSTER=y
CONFIG_NETFILTER_XT_MATCH_COMMENT=y
CONFIG_NETFILTER_XT_MATCH_CONNBYTES=y
CONFIG_NETFILTER_XT_MATCH_CONNLABEL=y
CONFIG_NETFILTER_XT_MATCH_CONNLIMIT=y
CONFIG_NETFILTER_XT_MATCH_CONNMARK=y
CONFIG_NETFILTER_XT_MATCH_CONNTRACK=y
CONFIG_NETFILTER_XT_MATCH_CPU=y
CONFIG_NETFILTER_XT_MATCH_DCCP=y
CONFIG_NETFILTER_XT_MATCH_DEVGROUP=y
CONFIG_NETFILTER_XT_MATCH_DSCP=y
CONFIG_NETFILTER_XT_MATCH_ECN=y
CONFIG_NETFILTER_XT_MATCH_ESP=y
CONFIG_NETFILTER_XT_MATCH_HASHLIMIT=y
CONFIG_NETFILTER_XT_MATCH_HELPER=y
CONFIG_NETFILTER_XT_MATCH_HL=y
CONFIG_NETFILTER_XT_MATCH_IPCOMP=y
CONFIG_NETFILTER_XT_MATCH_IPRANGE=y
CONFIG_NETFILTER_XT_MATCH_IPVS=y
CONFIG_NETFILTER_XT_MATCH_L2TP=y
CONFIG_NETFILTER_XT_MATCH_LENGTH=y
CONFIG_NETFILTER_XT_MATCH_LIMIT=y
CONFIG_NETFILTER_XT_MATCH_MAC=y
CONFIG_NETFILTER_XT_MATCH_MARK=y
CONFIG_NETFILTER_XT_MATCH_MULTIPORT=y
CONFIG_NETFILTER_XT_MATCH_NFACCT=y
CONFIG_NETFILTER_XT_MATCH_OSF=y
CONFIG_NETFILTER_XT_MATCH_OWNER=y
CONFIG_NETFILTER_XT_MATCH_POLICY=y
CONFIG_NETFILTER_XT_MATCH_PHYSDEV=y
CONFIG_NETFILTER_XT_MATCH_PKTTYPE=y
CONFIG_NETFILTER_XT_MATCH_QUOTA=y
CONFIG_NETFILTER_XT_MATCH_RATEEST=y
CONFIG_NETFILTER_XT_MATCH_REALM=y
CONFIG_NETFILTER_XT_MATCH_RECENT=y
CONFIG_NETFILTER_XT_MATCH_SCTP=y
CONFIG_NETFILTER_XT_MATCH_SOCKET=y
CONFIG_NETFILTER_XT_MATCH_STATE=y
CONFIG_NETFILTER_XT_MATCH_STATISTIC=y
CONFIG_NETFILTER_XT_MATCH_STRING=y
CONFIG_NETFILTER_XT_MATCH_TCPMSS=y
CONFIG_NETFILTER_XT_MATCH_TIME=y
CONFIG_NETFILTER_XT_MATCH_U32=y
# end of Core Netfilter Configuration

CONFIG_IP_SET=y
CONFIG_IP_SET_MAX=256
CONFIG_IP_SET_BITMAP_IP=y
CONFIG_IP_SET_BITMAP_IPMAC=y
CONFIG_IP_SET_BITMAP_PORT=y
CONFIG_IP_SET_HASH_IP=y
CONFIG_IP_SET_HASH_IPMARK=y
CONFIG_IP_SET_HASH_IPPORT=y
CONFIG_IP_SET_HASH_IPPORTIP=y
CONFIG_IP_SET_HASH_IPPORTNET=y
CONFIG_IP_SET_HASH_IPMAC=y
CONFIG_IP_SET_HASH_MAC=y
CONFIG_IP_SET_HASH_NETPORTNET=y
CONFIG_IP_SET_HASH_NET=y
CONFIG_IP_SET_HASH_NETNET=y
CONFIG_IP_SET_HASH_NETPORT=y
CONFIG_IP_SET_HASH_NETIFACE=y
CONFIG_IP_SET_LIST_SET=y
CONFIG_IP_VS=y
CONFIG_IP_VS_IPV6=y
CONFIG_IP_VS_DEBUG=y
CONFIG_IP_VS_TAB_BITS=12

#
# IPVS transport protocol load balancing support
#
CONFIG_IP_VS_PROTO_TCP=y
CONFIG_IP_VS_PROTO_UDP=y
CONFIG_IP_VS_PROTO_AH_ESP=y
CONFIG_IP_VS_PROTO_ESP=y
CONFIG_IP_VS_PROTO_AH=y
CONFIG_IP_VS_PROTO_SCTP=y

#
# IPVS scheduler
#
CONFIG_IP_VS_RR=y
CONFIG_IP_VS_WRR=y
CONFIG_IP_VS_LC=y
CONFIG_IP_VS_WLC=y
CONFIG_IP_VS_FO=y
CONFIG_IP_VS_OVF=y
CONFIG_IP_VS_LBLC=y
CONFIG_IP_VS_LBLCR=y
CONFIG_IP_VS_DH=y
CONFIG_IP_VS_SH=y
CONFIG_IP_VS_MH=y
CONFIG_IP_VS_SED=y
CONFIG_IP_VS_NQ=y
CONFIG_IP_VS_TWOS=y

#
# IPVS SH scheduler
#
CONFIG_IP_VS_SH_TAB_BITS=8

#
# IPVS MH scheduler
#
CONFIG_IP_VS_MH_TAB_INDEX=12

#
# IPVS application helper
#
CONFIG_IP_VS_FTP=y
CONFIG_IP_VS_NFCT=y
CONFIG_IP_VS_PE_SIP=y

#
# IP: Netfilter Configuration
#
CONFIG_NF_DEFRAG_IPV4=y
CONFIG_NF_SOCKET_IPV4=y
CONFIG_NF_TPROXY_IPV4=y
CONFIG_NF_TABLES_IPV4=y
CONFIG_NFT_REJECT_IPV4=y
CONFIG_NFT_DUP_IPV4=y
CONFIG_NFT_FIB_IPV4=y
CONFIG_NF_TABLES_ARP=y
CONFIG_NF_DUP_IPV4=y
CONFIG_NF_LOG_ARP=y
CONFIG_NF_LOG_IPV4=y
CONFIG_NF_REJECT_IPV4=y
CONFIG_NF_NAT_SNMP_BASIC=y
CONFIG_NF_NAT_PPTP=y
CONFIG_NF_NAT_H323=y
CONFIG_IP_NF_IPTABLES=y
CONFIG_IP_NF_MATCH_AH=y
CONFIG_IP_NF_MATCH_ECN=y
CONFIG_IP_NF_MATCH_RPFILTER=y
CONFIG_IP_NF_MATCH_TTL=y
CONFIG_IP_NF_FILTER=y
CONFIG_IP_NF_TARGET_REJECT=y
CONFIG_IP_NF_TARGET_SYNPROXY=y
CONFIG_IP_NF_NAT=y
CONFIG_IP_NF_TARGET_MASQUERADE=y
CONFIG_IP_NF_TARGET_NETMAP=y
CONFIG_IP_NF_TARGET_REDIRECT=y
CONFIG_IP_NF_MANGLE=y
CONFIG_IP_NF_TARGET_CLUSTERIP=y
CONFIG_IP_NF_TARGET_ECN=y
CONFIG_IP_NF_TARGET_TTL=y
CONFIG_IP_NF_RAW=y
CONFIG_IP_NF_SECURITY=y
CONFIG_IP_NF_ARPTABLES=y
CONFIG_IP_NF_ARPFILTER=y
CONFIG_IP_NF_ARP_MANGLE=y
# end of IP: Netfilter Configuration

#
# IPv6: Netfilter Configuration
#
CONFIG_NF_SOCKET_IPV6=y
CONFIG_NF_TPROXY_IPV6=y
CONFIG_NF_TABLES_IPV6=y
CONFIG_NFT_REJECT_IPV6=y
CONFIG_NFT_DUP_IPV6=y
CONFIG_NFT_FIB_IPV6=y
CONFIG_NF_DUP_IPV6=y
CONFIG_NF_REJECT_IPV6=y
CONFIG_NF_LOG_IPV6=y
CONFIG_IP6_NF_IPTABLES=y
CONFIG_IP6_NF_MATCH_AH=y
CONFIG_IP6_NF_MATCH_EUI64=y
CONFIG_IP6_NF_MATCH_FRAG=y
CONFIG_IP6_NF_MATCH_OPTS=y
CONFIG_IP6_NF_MATCH_HL=y
CONFIG_IP6_NF_MATCH_IPV6HEADER=y
CONFIG_IP6_NF_MATCH_MH=y
CONFIG_IP6_NF_MATCH_RPFILTER=y
CONFIG_IP6_NF_MATCH_RT=y
CONFIG_IP6_NF_MATCH_SRH=y
CONFIG_IP6_NF_TARGET_HL=y
CONFIG_IP6_NF_FILTER=y
CONFIG_IP6_NF_TARGET_REJECT=y
CONFIG_IP6_NF_TARGET_SYNPROXY=y
CONFIG_IP6_NF_MANGLE=y
CONFIG_IP6_NF_RAW=y
CONFIG_IP6_NF_SECURITY=y
CONFIG_IP6_NF_NAT=y
CONFIG_IP6_NF_TARGET_MASQUERADE=y
CONFIG_IP6_NF_TARGET_NPT=y
# end of IPv6: Netfilter Configuration

CONFIG_NF_DEFRAG_IPV6=y

#
# DECnet: Netfilter Configuration
#
CONFIG_DECNET_NF_GRABULATOR=y
# end of DECnet: Netfilter Configuration

CONFIG_NF_TABLES_BRIDGE=y
CONFIG_NFT_BRIDGE_META=y
CONFIG_NFT_BRIDGE_REJECT=y
CONFIG_NF_CONNTRACK_BRIDGE=y
CONFIG_BRIDGE_NF_EBTABLES=y
CONFIG_BRIDGE_EBT_BROUTE=y
CONFIG_BRIDGE_EBT_T_FILTER=y
CONFIG_BRIDGE_EBT_T_NAT=y
CONFIG_BRIDGE_EBT_802_3=y
CONFIG_BRIDGE_EBT_AMONG=y
CONFIG_BRIDGE_EBT_ARP=y
CONFIG_BRIDGE_EBT_IP=y
CONFIG_BRIDGE_EBT_IP6=y
CONFIG_BRIDGE_EBT_LIMIT=y
CONFIG_BRIDGE_EBT_MARK=y
CONFIG_BRIDGE_EBT_PKTTYPE=y
CONFIG_BRIDGE_EBT_STP=y
CONFIG_BRIDGE_EBT_VLAN=y
CONFIG_BRIDGE_EBT_ARPREPLY=y
CONFIG_BRIDGE_EBT_DNAT=y
CONFIG_BRIDGE_EBT_MARK_T=y
CONFIG_BRIDGE_EBT_REDIRECT=y
CONFIG_BRIDGE_EBT_SNAT=y
CONFIG_BRIDGE_EBT_LOG=y
CONFIG_BRIDGE_EBT_NFLOG=y
CONFIG_BPFILTER=y
CONFIG_BPFILTER_UMH=y
CONFIG_IP_DCCP=y
CONFIG_INET_DCCP_DIAG=y

#
# DCCP CCIDs Configuration
#
CONFIG_IP_DCCP_CCID2_DEBUG=y
CONFIG_IP_DCCP_CCID3=y
CONFIG_IP_DCCP_CCID3_DEBUG=y
CONFIG_IP_DCCP_TFRC_LIB=y
CONFIG_IP_DCCP_TFRC_DEBUG=y
# end of DCCP CCIDs Configuration

#
# DCCP Kernel Hacking
#
CONFIG_IP_DCCP_DEBUG=y
# end of DCCP Kernel Hacking

CONFIG_IP_SCTP=y
CONFIG_SCTP_DBG_OBJCNT=y
CONFIG_SCTP_DEFAULT_COOKIE_HMAC_MD5=y
# CONFIG_SCTP_DEFAULT_COOKIE_HMAC_SHA1 is not set
# CONFIG_SCTP_DEFAULT_COOKIE_HMAC_NONE is not set
CONFIG_SCTP_COOKIE_HMAC_MD5=y
CONFIG_SCTP_COOKIE_HMAC_SHA1=y
CONFIG_INET_SCTP_DIAG=y
CONFIG_RDS=y
CONFIG_RDS_RDMA=y
CONFIG_RDS_TCP=y
CONFIG_RDS_DEBUG=y
CONFIG_TIPC=y
CONFIG_TIPC_MEDIA_IB=y
CONFIG_TIPC_MEDIA_UDP=y
CONFIG_TIPC_CRYPTO=y
CONFIG_TIPC_DIAG=y
CONFIG_ATM=y
CONFIG_ATM_CLIP=y
CONFIG_ATM_CLIP_NO_ICMP=y
CONFIG_ATM_LANE=y
CONFIG_ATM_MPOA=y
CONFIG_ATM_BR2684=y
CONFIG_ATM_BR2684_IPFILTER=y
CONFIG_L2TP=y
CONFIG_L2TP_DEBUGFS=y
CONFIG_L2TP_V3=y
CONFIG_L2TP_IP=y
CONFIG_L2TP_ETH=y
CONFIG_STP=y
CONFIG_GARP=y
CONFIG_MRP=y
CONFIG_BRIDGE=y
CONFIG_BRIDGE_IGMP_SNOOPING=y
CONFIG_BRIDGE_VLAN_FILTERING=y
CONFIG_BRIDGE_MRP=y
CONFIG_BRIDGE_CFM=y
CONFIG_NET_DSA=y
CONFIG_NET_DSA_TAG_AR9331=y
CONFIG_NET_DSA_TAG_BRCM_COMMON=y
CONFIG_NET_DSA_TAG_BRCM=y
CONFIG_NET_DSA_TAG_BRCM_LEGACY=y
CONFIG_NET_DSA_TAG_BRCM_PREPEND=y
CONFIG_NET_DSA_TAG_HELLCREEK=y
CONFIG_NET_DSA_TAG_GSWIP=y
CONFIG_NET_DSA_TAG_DSA_COMMON=y
CONFIG_NET_DSA_TAG_DSA=y
CONFIG_NET_DSA_TAG_EDSA=y
CONFIG_NET_DSA_TAG_MTK=y
CONFIG_NET_DSA_TAG_KSZ=y
CONFIG_NET_DSA_TAG_OCELOT=y
CONFIG_NET_DSA_TAG_OCELOT_8021Q=y
CONFIG_NET_DSA_TAG_QCA=y
CONFIG_NET_DSA_TAG_RTL4_A=y
CONFIG_NET_DSA_TAG_RTL8_4=y
CONFIG_NET_DSA_TAG_RZN1_A5PSW=y
CONFIG_NET_DSA_TAG_LAN9303=y
CONFIG_NET_DSA_TAG_SJA1105=y
CONFIG_NET_DSA_TAG_TRAILER=y
CONFIG_NET_DSA_TAG_XRS700X=y
CONFIG_VLAN_8021Q=y
CONFIG_VLAN_8021Q_GVRP=y
CONFIG_VLAN_8021Q_MVRP=y
CONFIG_DECNET=y
CONFIG_DECNET_ROUTER=y
CONFIG_LLC=y
CONFIG_LLC2=y
CONFIG_ATALK=y
CONFIG_DEV_APPLETALK=y
CONFIG_IPDDP=y
CONFIG_IPDDP_ENCAP=y
CONFIG_X25=y
CONFIG_LAPB=y
CONFIG_PHONET=y
CONFIG_6LOWPAN=y
CONFIG_6LOWPAN_DEBUGFS=y
CONFIG_6LOWPAN_NHC=y
CONFIG_6LOWPAN_NHC_DEST=y
CONFIG_6LOWPAN_NHC_FRAGMENT=y
CONFIG_6LOWPAN_NHC_HOP=y
CONFIG_6LOWPAN_NHC_IPV6=y
CONFIG_6LOWPAN_NHC_MOBILITY=y
CONFIG_6LOWPAN_NHC_ROUTING=y
CONFIG_6LOWPAN_NHC_UDP=y
CONFIG_6LOWPAN_GHC_EXT_HDR_HOP=y
CONFIG_6LOWPAN_GHC_UDP=y
CONFIG_6LOWPAN_GHC_ICMPV6=y
CONFIG_6LOWPAN_GHC_EXT_HDR_DEST=y
CONFIG_6LOWPAN_GHC_EXT_HDR_FRAG=y
CONFIG_6LOWPAN_GHC_EXT_HDR_ROUTE=y
CONFIG_IEEE802154=y
CONFIG_IEEE802154_NL802154_EXPERIMENTAL=y
CONFIG_IEEE802154_SOCKET=y
CONFIG_IEEE802154_6LOWPAN=y
CONFIG_MAC802154=y
CONFIG_NET_SCHED=y

#
# Queueing/Scheduling
#
CONFIG_NET_SCH_CBQ=y
CONFIG_NET_SCH_HTB=y
CONFIG_NET_SCH_HFSC=y
CONFIG_NET_SCH_ATM=y
CONFIG_NET_SCH_PRIO=y
CONFIG_NET_SCH_MULTIQ=y
CONFIG_NET_SCH_RED=y
CONFIG_NET_SCH_SFB=y
CONFIG_NET_SCH_SFQ=y
CONFIG_NET_SCH_TEQL=y
CONFIG_NET_SCH_TBF=y
CONFIG_NET_SCH_CBS=y
CONFIG_NET_SCH_ETF=y
CONFIG_NET_SCH_TAPRIO=y
CONFIG_NET_SCH_GRED=y
CONFIG_NET_SCH_DSMARK=y
CONFIG_NET_SCH_NETEM=y
CONFIG_NET_SCH_DRR=y
CONFIG_NET_SCH_MQPRIO=y
CONFIG_NET_SCH_SKBPRIO=y
CONFIG_NET_SCH_CHOKE=y
CONFIG_NET_SCH_QFQ=y
CONFIG_NET_SCH_CODEL=y
CONFIG_NET_SCH_FQ_CODEL=y
CONFIG_NET_SCH_CAKE=y
CONFIG_NET_SCH_FQ=y
CONFIG_NET_SCH_HHF=y
CONFIG_NET_SCH_PIE=y
CONFIG_NET_SCH_FQ_PIE=y
CONFIG_NET_SCH_INGRESS=y
CONFIG_NET_SCH_PLUG=y
CONFIG_NET_SCH_ETS=y
CONFIG_NET_SCH_DEFAULT=y
# CONFIG_DEFAULT_FQ is not set
# CONFIG_DEFAULT_CODEL is not set
# CONFIG_DEFAULT_FQ_CODEL is not set
# CONFIG_DEFAULT_FQ_PIE is not set
# CONFIG_DEFAULT_SFQ is not set
CONFIG_DEFAULT_PFIFO_FAST=y
CONFIG_DEFAULT_NET_SCH="pfifo_fast"

#
# Classification
#
CONFIG_NET_CLS=y
CONFIG_NET_CLS_BASIC=y
CONFIG_NET_CLS_TCINDEX=y
CONFIG_NET_CLS_ROUTE4=y
CONFIG_NET_CLS_FW=y
CONFIG_NET_CLS_U32=y
CONFIG_CLS_U32_PERF=y
CONFIG_CLS_U32_MARK=y
CONFIG_NET_CLS_RSVP=y
CONFIG_NET_CLS_RSVP6=y
CONFIG_NET_CLS_FLOW=y
CONFIG_NET_CLS_CGROUP=y
CONFIG_NET_CLS_BPF=y
CONFIG_NET_CLS_FLOWER=y
CONFIG_NET_CLS_MATCHALL=y
CONFIG_NET_EMATCH=y
CONFIG_NET_EMATCH_STACK=32
CONFIG_NET_EMATCH_CMP=y
CONFIG_NET_EMATCH_NBYTE=y
CONFIG_NET_EMATCH_U32=y
CONFIG_NET_EMATCH_META=y
CONFIG_NET_EMATCH_TEXT=y
CONFIG_NET_EMATCH_CANID=y
CONFIG_NET_EMATCH_IPSET=y
CONFIG_NET_EMATCH_IPT=y
CONFIG_NET_CLS_ACT=y
CONFIG_NET_ACT_POLICE=y
CONFIG_NET_ACT_GACT=y
CONFIG_GACT_PROB=y
CONFIG_NET_ACT_MIRRED=y
CONFIG_NET_ACT_SAMPLE=y
CONFIG_NET_ACT_IPT=y
CONFIG_NET_ACT_NAT=y
CONFIG_NET_ACT_PEDIT=y
CONFIG_NET_ACT_SIMP=y
CONFIG_NET_ACT_SKBEDIT=y
CONFIG_NET_ACT_CSUM=y
CONFIG_NET_ACT_MPLS=y
CONFIG_NET_ACT_VLAN=y
CONFIG_NET_ACT_BPF=y
CONFIG_NET_ACT_CONNMARK=y
CONFIG_NET_ACT_CTINFO=y
CONFIG_NET_ACT_SKBMOD=y
CONFIG_NET_ACT_IFE=y
CONFIG_NET_ACT_TUNNEL_KEY=y
CONFIG_NET_ACT_CT=y
CONFIG_NET_ACT_GATE=y
CONFIG_NET_IFE_SKBMARK=y
CONFIG_NET_IFE_SKBPRIO=y
CONFIG_NET_IFE_SKBTCINDEX=y
CONFIG_NET_TC_SKB_EXT=y
CONFIG_NET_SCH_FIFO=y
CONFIG_DCB=y
CONFIG_DNS_RESOLVER=y
CONFIG_BATMAN_ADV=y
CONFIG_BATMAN_ADV_BATMAN_V=y
CONFIG_BATMAN_ADV_BLA=y
CONFIG_BATMAN_ADV_DAT=y
CONFIG_BATMAN_ADV_NC=y
CONFIG_BATMAN_ADV_MCAST=y
CONFIG_BATMAN_ADV_DEBUG=y
CONFIG_BATMAN_ADV_TRACING=y
CONFIG_OPENVSWITCH=y
CONFIG_OPENVSWITCH_GRE=y
CONFIG_OPENVSWITCH_VXLAN=y
CONFIG_OPENVSWITCH_GENEVE=y
CONFIG_VSOCKETS=y
CONFIG_VSOCKETS_DIAG=y
CONFIG_VSOCKETS_LOOPBACK=y
CONFIG_VMWARE_VMCI_VSOCKETS=y
CONFIG_VIRTIO_VSOCKETS=y
CONFIG_VIRTIO_VSOCKETS_COMMON=y
CONFIG_HYPERV_VSOCKETS=y
CONFIG_NETLINK_DIAG=y
CONFIG_MPLS=y
CONFIG_NET_MPLS_GSO=y
CONFIG_MPLS_ROUTING=y
CONFIG_MPLS_IPTUNNEL=y
CONFIG_NET_NSH=y
CONFIG_HSR=y
CONFIG_NET_SWITCHDEV=y
CONFIG_NET_L3_MASTER_DEV=y
CONFIG_QRTR=y
CONFIG_QRTR_SMD=y
CONFIG_QRTR_TUN=y
CONFIG_QRTR_MHI=y
CONFIG_NET_NCSI=y
CONFIG_NCSI_OEM_CMD_GET_MAC=y
CONFIG_NCSI_OEM_CMD_KEEP_PHY=y
CONFIG_PCPU_DEV_REFCNT=y
CONFIG_RPS=y
CONFIG_RFS_ACCEL=y
CONFIG_SOCK_RX_QUEUE_MAPPING=y
CONFIG_XPS=y
CONFIG_CGROUP_NET_PRIO=y
CONFIG_CGROUP_NET_CLASSID=y
CONFIG_NET_RX_BUSY_POLL=y
CONFIG_BQL=y
CONFIG_BPF_STREAM_PARSER=y
CONFIG_NET_FLOW_LIMIT=y

#
# Network testing
#
CONFIG_NET_PKTGEN=y
CONFIG_NET_DROP_MONITOR=y
# end of Network testing
# end of Networking options

CONFIG_HAMRADIO=y

#
# Packet Radio protocols
#
CONFIG_AX25=y
CONFIG_AX25_DAMA_SLAVE=y
CONFIG_NETROM=y
CONFIG_ROSE=y

#
# AX.25 network device drivers
#
CONFIG_MKISS=y
CONFIG_6PACK=y
CONFIG_BPQETHER=y
CONFIG_BAYCOM_SER_FDX=y
CONFIG_BAYCOM_SER_HDX=y
CONFIG_BAYCOM_PAR=y
CONFIG_YAM=y
# end of AX.25 network device drivers

CONFIG_CAN=y
CONFIG_CAN_RAW=y
CONFIG_CAN_BCM=y
CONFIG_CAN_GW=y
CONFIG_CAN_J1939=y
CONFIG_CAN_ISOTP=y
CONFIG_BT=y
CONFIG_BT_BREDR=y
CONFIG_BT_RFCOMM=y
CONFIG_BT_RFCOMM_TTY=y
CONFIG_BT_BNEP=y
CONFIG_BT_BNEP_MC_FILTER=y
CONFIG_BT_BNEP_PROTO_FILTER=y
CONFIG_BT_CMTP=y
CONFIG_BT_HIDP=y
CONFIG_BT_HS=y
CONFIG_BT_LE=y
CONFIG_BT_6LOWPAN=y
CONFIG_BT_LEDS=y
CONFIG_BT_MSFTEXT=y
CONFIG_BT_AOSPEXT=y
CONFIG_BT_DEBUGFS=y
CONFIG_BT_SELFTEST=y
CONFIG_BT_SELFTEST_ECDH=y
CONFIG_BT_SELFTEST_SMP=y

#
# Bluetooth device drivers
#
CONFIG_BT_INTEL=y
CONFIG_BT_BCM=y
CONFIG_BT_RTL=y
CONFIG_BT_QCA=y
CONFIG_BT_MTK=y
CONFIG_BT_HCIBTUSB=y
CONFIG_BT_HCIBTUSB_AUTOSUSPEND=y
CONFIG_BT_HCIBTUSB_BCM=y
CONFIG_BT_HCIBTUSB_MTK=y
CONFIG_BT_HCIBTUSB_RTL=y
CONFIG_BT_HCIBTSDIO=y
CONFIG_BT_HCIUART=y
CONFIG_BT_HCIUART_SERDEV=y
CONFIG_BT_HCIUART_H4=y
CONFIG_BT_HCIUART_NOKIA=y
CONFIG_BT_HCIUART_BCSP=y
CONFIG_BT_HCIUART_ATH3K=y
CONFIG_BT_HCIUART_LL=y
CONFIG_BT_HCIUART_3WIRE=y
CONFIG_BT_HCIUART_INTEL=y
CONFIG_BT_HCIUART_BCM=y
CONFIG_BT_HCIUART_RTL=y
CONFIG_BT_HCIUART_QCA=y
CONFIG_BT_HCIUART_AG6XX=y
CONFIG_BT_HCIUART_MRVL=y
CONFIG_BT_HCIBCM203X=y
CONFIG_BT_HCIBPA10X=y
CONFIG_BT_HCIBFUSB=y
CONFIG_BT_HCIDTL1=y
CONFIG_BT_HCIBT3C=y
CONFIG_BT_HCIBLUECARD=y
CONFIG_BT_HCIVHCI=y
CONFIG_BT_MRVL=y
CONFIG_BT_MRVL_SDIO=y
CONFIG_BT_ATH3K=y
CONFIG_BT_MTKSDIO=y
CONFIG_BT_MTKUART=y
CONFIG_BT_HCIRSI=y
CONFIG_BT_VIRTIO=y
# end of Bluetooth device drivers

CONFIG_AF_RXRPC=y
CONFIG_AF_RXRPC_IPV6=y
CONFIG_AF_RXRPC_INJECT_LOSS=y
CONFIG_AF_RXRPC_DEBUG=y
CONFIG_RXKAD=y
CONFIG_AF_KCM=y
CONFIG_STREAM_PARSER=y
CONFIG_MCTP=y
CONFIG_MCTP_TEST=y
CONFIG_MCTP_FLOWS=y
CONFIG_FIB_RULES=y
CONFIG_WIRELESS=y
CONFIG_WIRELESS_EXT=y
CONFIG_WEXT_CORE=y
CONFIG_WEXT_PROC=y
CONFIG_WEXT_SPY=y
CONFIG_WEXT_PRIV=y
CONFIG_CFG80211=y
CONFIG_NL80211_TESTMODE=y
CONFIG_CFG80211_DEVELOPER_WARNINGS=y
CONFIG_CFG80211_CERTIFICATION_ONUS=y
CONFIG_CFG80211_REQUIRE_SIGNED_REGDB=y
CONFIG_CFG80211_USE_KERNEL_REGDB_KEYS=y
CONFIG_CFG80211_EXTRA_REGDB_KEYDIR=""
CONFIG_CFG80211_REG_CELLULAR_HINTS=y
CONFIG_CFG80211_REG_RELAX_NO_IR=y
CONFIG_CFG80211_DEFAULT_PS=y
CONFIG_CFG80211_DEBUGFS=y
CONFIG_CFG80211_CRDA_SUPPORT=y
CONFIG_CFG80211_WEXT=y
CONFIG_CFG80211_WEXT_EXPORT=y
CONFIG_LIB80211=y
CONFIG_LIB80211_CRYPT_WEP=y
CONFIG_LIB80211_CRYPT_CCMP=y
CONFIG_LIB80211_CRYPT_TKIP=y
CONFIG_LIB80211_DEBUG=y
CONFIG_MAC80211=y
CONFIG_MAC80211_HAS_RC=y
CONFIG_MAC80211_RC_MINSTREL=y
CONFIG_MAC80211_RC_DEFAULT_MINSTREL=y
CONFIG_MAC80211_RC_DEFAULT="minstrel_ht"
CONFIG_MAC80211_MESH=y
CONFIG_MAC80211_LEDS=y
CONFIG_MAC80211_DEBUGFS=y
CONFIG_MAC80211_MESSAGE_TRACING=y
CONFIG_MAC80211_DEBUG_MENU=y
CONFIG_MAC80211_NOINLINE=y
CONFIG_MAC80211_VERBOSE_DEBUG=y
CONFIG_MAC80211_MLME_DEBUG=y
CONFIG_MAC80211_STA_DEBUG=y
CONFIG_MAC80211_HT_DEBUG=y
CONFIG_MAC80211_OCB_DEBUG=y
CONFIG_MAC80211_IBSS_DEBUG=y
CONFIG_MAC80211_PS_DEBUG=y
CONFIG_MAC80211_MPL_DEBUG=y
CONFIG_MAC80211_MPATH_DEBUG=y
CONFIG_MAC80211_MHWMP_DEBUG=y
CONFIG_MAC80211_MESH_SYNC_DEBUG=y
CONFIG_MAC80211_MESH_CSA_DEBUG=y
CONFIG_MAC80211_MESH_PS_DEBUG=y
CONFIG_MAC80211_TDLS_DEBUG=y
CONFIG_MAC80211_DEBUG_COUNTERS=y
CONFIG_MAC80211_STA_HASH_MAX_SIZE=0
CONFIG_RFKILL=y
CONFIG_RFKILL_LEDS=y
CONFIG_RFKILL_INPUT=y
CONFIG_RFKILL_GPIO=y
CONFIG_NET_9P=y
CONFIG_NET_9P_FD=y
CONFIG_NET_9P_VIRTIO=y
CONFIG_NET_9P_XEN=y
CONFIG_NET_9P_RDMA=y
CONFIG_NET_9P_DEBUG=y
CONFIG_CAIF=y
CONFIG_CAIF_DEBUG=y
CONFIG_CAIF_NETDEV=y
CONFIG_CAIF_USB=y
CONFIG_CEPH_LIB=y
CONFIG_CEPH_LIB_PRETTYDEBUG=y
CONFIG_CEPH_LIB_USE_DNS_RESOLVER=y
CONFIG_NFC=y
CONFIG_NFC_DIGITAL=y
CONFIG_NFC_NCI=y
CONFIG_NFC_NCI_SPI=y
CONFIG_NFC_NCI_UART=y
CONFIG_NFC_HCI=y
CONFIG_NFC_SHDLC=y

#
# Near Field Communication (NFC) devices
#
CONFIG_NFC_TRF7970A=y
CONFIG_NFC_MEI_PHY=y
CONFIG_NFC_SIM=y
CONFIG_NFC_PORT100=y
CONFIG_NFC_VIRTUAL_NCI=y
CONFIG_NFC_FDP=y
CONFIG_NFC_FDP_I2C=y
CONFIG_NFC_PN544=y
CONFIG_NFC_PN544_I2C=y
CONFIG_NFC_PN544_MEI=y
CONFIG_NFC_PN533=y
CONFIG_NFC_PN533_USB=y
CONFIG_NFC_PN533_I2C=y
CONFIG_NFC_PN532_UART=y
CONFIG_NFC_MICROREAD=y
CONFIG_NFC_MICROREAD_I2C=y
CONFIG_NFC_MICROREAD_MEI=y
CONFIG_NFC_MRVL=y
CONFIG_NFC_MRVL_USB=y
CONFIG_NFC_MRVL_UART=y
CONFIG_NFC_MRVL_I2C=y
CONFIG_NFC_MRVL_SPI=y
CONFIG_NFC_ST21NFCA=y
CONFIG_NFC_ST21NFCA_I2C=y
CONFIG_NFC_ST_NCI=y
CONFIG_NFC_ST_NCI_I2C=y
CONFIG_NFC_ST_NCI_SPI=y
CONFIG_NFC_NXP_NCI=y
CONFIG_NFC_NXP_NCI_I2C=y
CONFIG_NFC_S3FWRN5=y
CONFIG_NFC_S3FWRN5_I2C=y
CONFIG_NFC_S3FWRN82_UART=y
CONFIG_NFC_ST95HF=y
# end of Near Field Communication (NFC) devices

CONFIG_PSAMPLE=y
CONFIG_NET_IFE=y
CONFIG_LWTUNNEL=y
CONFIG_LWTUNNEL_BPF=y
CONFIG_DST_CACHE=y
CONFIG_GRO_CELLS=y
CONFIG_SOCK_VALIDATE_XMIT=y
CONFIG_NET_SELFTESTS=y
CONFIG_NET_SOCK_MSG=y
CONFIG_NET_DEVLINK=y
CONFIG_PAGE_POOL=y
CONFIG_PAGE_POOL_STATS=y
CONFIG_FAILOVER=y
CONFIG_ETHTOOL_NETLINK=y
CONFIG_NETDEV_ADDR_LIST_TEST=y

#
# Device Drivers
#
CONFIG_HAVE_EISA=y
CONFIG_EISA=y
CONFIG_EISA_VLB_PRIMING=y
CONFIG_EISA_PCI_EISA=y
CONFIG_EISA_VIRTUAL_ROOT=y
CONFIG_EISA_NAMES=y
CONFIG_HAVE_PCI=y
CONFIG_PCI=y
CONFIG_PCI_DOMAINS=y
CONFIG_PCIEPORTBUS=y
CONFIG_HOTPLUG_PCI_PCIE=y
CONFIG_PCIEAER=y
CONFIG_PCIEAER_INJECT=y
CONFIG_PCIE_ECRC=y
CONFIG_PCIEASPM=y
CONFIG_PCIEASPM_DEFAULT=y
# CONFIG_PCIEASPM_POWERSAVE is not set
# CONFIG_PCIEASPM_POWER_SUPERSAVE is not set
# CONFIG_PCIEASPM_PERFORMANCE is not set
CONFIG_PCIE_PME=y
CONFIG_PCIE_DPC=y
CONFIG_PCIE_PTM=y
CONFIG_PCIE_EDR=y
CONFIG_PCI_MSI=y
CONFIG_PCI_MSI_IRQ_DOMAIN=y
CONFIG_PCI_QUIRKS=y
CONFIG_PCI_DEBUG=y
CONFIG_PCI_REALLOC_ENABLE_AUTO=y
CONFIG_PCI_STUB=y
CONFIG_PCI_PF_STUB=y
CONFIG_XEN_PCIDEV_FRONTEND=y
CONFIG_PCI_ATS=y
CONFIG_PCI_DOE=y
CONFIG_PCI_ECAM=y
CONFIG_PCI_LOCKLESS_CONFIG=y
CONFIG_PCI_IOV=y
CONFIG_PCI_PRI=y
CONFIG_PCI_PASID=y
CONFIG_PCI_P2PDMA=y
CONFIG_PCI_LABEL=y
CONFIG_PCI_HYPERV=y
# CONFIG_PCIE_BUS_TUNE_OFF is not set
CONFIG_PCIE_BUS_DEFAULT=y
# CONFIG_PCIE_BUS_SAFE is not set
# CONFIG_PCIE_BUS_PERFORMANCE is not set
# CONFIG_PCIE_BUS_PEER2PEER is not set
CONFIG_VGA_ARB=y
CONFIG_VGA_ARB_MAX_GPUS=16
CONFIG_HOTPLUG_PCI=y
CONFIG_HOTPLUG_PCI_ACPI=y
CONFIG_HOTPLUG_PCI_ACPI_IBM=y
CONFIG_HOTPLUG_PCI_CPCI=y
CONFIG_HOTPLUG_PCI_CPCI_ZT5550=y
CONFIG_HOTPLUG_PCI_CPCI_GENERIC=y
CONFIG_HOTPLUG_PCI_SHPC=y

#
# PCI controller drivers
#
CONFIG_PCI_FTPCI100=y
CONFIG_PCI_HOST_COMMON=y
CONFIG_PCI_HOST_GENERIC=y
CONFIG_PCIE_XILINX=y
CONFIG_VMD=y
CONFIG_PCI_HYPERV_INTERFACE=y
CONFIG_PCIE_MICROCHIP_HOST=y

#
# DesignWare PCI Core Support
#
CONFIG_PCIE_DW=y
CONFIG_PCIE_DW_HOST=y
CONFIG_PCIE_DW_EP=y
CONFIG_PCIE_DW_PLAT=y
CONFIG_PCIE_DW_PLAT_HOST=y
CONFIG_PCIE_DW_PLAT_EP=y
CONFIG_PCIE_INTEL_GW=y
CONFIG_PCI_MESON=y
# end of DesignWare PCI Core Support

#
# Mobiveil PCIe Core Support
#
# end of Mobiveil PCIe Core Support

#
# Cadence PCIe controllers support
#
CONFIG_PCIE_CADENCE=y
CONFIG_PCIE_CADENCE_HOST=y
CONFIG_PCIE_CADENCE_EP=y
CONFIG_PCIE_CADENCE_PLAT=y
CONFIG_PCIE_CADENCE_PLAT_HOST=y
CONFIG_PCIE_CADENCE_PLAT_EP=y
CONFIG_PCI_J721E=y
CONFIG_PCI_J721E_HOST=y
CONFIG_PCI_J721E_EP=y
# end of Cadence PCIe controllers support
# end of PCI controller drivers

#
# PCI Endpoint
#
CONFIG_PCI_ENDPOINT=y
CONFIG_PCI_ENDPOINT_CONFIGFS=y
CONFIG_PCI_EPF_TEST=y
CONFIG_PCI_EPF_NTB=y
CONFIG_PCI_EPF_VNTB=y
# end of PCI Endpoint

#
# PCI switch controller drivers
#
CONFIG_PCI_SW_SWITCHTEC=y
# end of PCI switch controller drivers

CONFIG_CXL_BUS=y
CONFIG_CXL_PCI=y
CONFIG_CXL_MEM_RAW_COMMANDS=y
CONFIG_CXL_ACPI=y
CONFIG_CXL_PMEM=y
CONFIG_CXL_MEM=y
CONFIG_CXL_PORT=y
CONFIG_CXL_SUSPEND=y
CONFIG_CXL_REGION=y
CONFIG_PCCARD=y
CONFIG_PCMCIA=y
CONFIG_PCMCIA_LOAD_CIS=y
CONFIG_CARDBUS=y

#
# PC-card bridges
#
CONFIG_YENTA=y
CONFIG_YENTA_O2=y
CONFIG_YENTA_RICOH=y
CONFIG_YENTA_TI=y
CONFIG_YENTA_ENE_TUNE=y
CONFIG_YENTA_TOSHIBA=y
CONFIG_PD6729=y
CONFIG_I82092=y
CONFIG_PCCARD_NONSTATIC=y
CONFIG_RAPIDIO=y
CONFIG_RAPIDIO_TSI721=y
CONFIG_RAPIDIO_DISC_TIMEOUT=30
CONFIG_RAPIDIO_ENABLE_RX_TX_PORTS=y
CONFIG_RAPIDIO_DMA_ENGINE=y
CONFIG_RAPIDIO_DEBUG=y
CONFIG_RAPIDIO_ENUM_BASIC=y
CONFIG_RAPIDIO_CHMAN=y
CONFIG_RAPIDIO_MPORT_CDEV=y

#
# RapidIO Switch drivers
#
CONFIG_RAPIDIO_CPS_XX=y
CONFIG_RAPIDIO_CPS_GEN2=y
CONFIG_RAPIDIO_RXS_GEN3=y
# end of RapidIO Switch drivers

#
# Generic Driver Options
#
CONFIG_AUXILIARY_BUS=y
CONFIG_UEVENT_HELPER=y
CONFIG_UEVENT_HELPER_PATH=""
CONFIG_DEVTMPFS=y
CONFIG_DEVTMPFS_MOUNT=y
CONFIG_DEVTMPFS_SAFE=y
CONFIG_STANDALONE=y
CONFIG_PREVENT_FIRMWARE_BUILD=y

#
# Firmware loader
#
CONFIG_FW_LOADER=y
CONFIG_FW_LOADER_PAGED_BUF=y
CONFIG_FW_LOADER_SYSFS=y
CONFIG_EXTRA_FIRMWARE=""
CONFIG_FW_LOADER_USER_HELPER=y
CONFIG_FW_LOADER_USER_HELPER_FALLBACK=y
CONFIG_FW_LOADER_COMPRESS=y
CONFIG_FW_LOADER_COMPRESS_XZ=y
CONFIG_FW_LOADER_COMPRESS_ZSTD=y
CONFIG_FW_CACHE=y
CONFIG_FW_UPLOAD=y
# end of Firmware loader

CONFIG_WANT_DEV_COREDUMP=y
CONFIG_ALLOW_DEV_COREDUMP=y
CONFIG_DEV_COREDUMP=y
CONFIG_DEBUG_DRIVER=y
CONFIG_DEBUG_DEVRES=y
CONFIG_DEBUG_TEST_DRIVER_REMOVE=y
CONFIG_PM_QOS_KUNIT_TEST=y
CONFIG_HMEM_REPORTING=y
CONFIG_TEST_ASYNC_DRIVER_PROBE=m
CONFIG_DRIVER_PE_KUNIT_TEST=y
CONFIG_SYS_HYPERVISOR=y
CONFIG_GENERIC_CPU_AUTOPROBE=y
CONFIG_GENERIC_CPU_VULNERABILITIES=y
CONFIG_REGMAP=y
CONFIG_REGMAP_I2C=y
CONFIG_REGMAP_SLIMBUS=y
CONFIG_REGMAP_SPI=y
CONFIG_REGMAP_SPMI=y
CONFIG_REGMAP_W1=y
CONFIG_REGMAP_MMIO=y
CONFIG_REGMAP_IRQ=y
CONFIG_REGMAP_SOUNDWIRE=y
CONFIG_REGMAP_SOUNDWIRE_MBQ=y
CONFIG_REGMAP_SCCB=y
CONFIG_REGMAP_I3C=y
CONFIG_REGMAP_SPI_AVMM=y
CONFIG_DMA_SHARED_BUFFER=y
CONFIG_DMA_FENCE_TRACE=y
# end of Generic Driver Options

#
# Bus devices
#
CONFIG_MOXTET=y
CONFIG_MHI_BUS=y
CONFIG_MHI_BUS_DEBUG=y
CONFIG_MHI_BUS_PCI_GENERIC=y
CONFIG_MHI_BUS_EP=y
# end of Bus devices

CONFIG_CONNECTOR=y
CONFIG_PROC_EVENTS=y

#
# Firmware Drivers
#

#
# ARM System Control and Management Interface Protocol
#
# end of ARM System Control and Management Interface Protocol

CONFIG_EDD=y
CONFIG_EDD_OFF=y
CONFIG_FIRMWARE_MEMMAP=y
CONFIG_DMIID=y
CONFIG_DMI_SYSFS=y
CONFIG_DMI_SCAN_MACHINE_NON_EFI_FALLBACK=y
CONFIG_ISCSI_IBFT_FIND=y
CONFIG_ISCSI_IBFT=y
CONFIG_FW_CFG_SYSFS=y
CONFIG_FW_CFG_SYSFS_CMDLINE=y
CONFIG_SYSFB=y
CONFIG_SYSFB_SIMPLEFB=y
CONFIG_CS_DSP=y
CONFIG_GOOGLE_FIRMWARE=y
CONFIG_GOOGLE_SMI=y
CONFIG_GOOGLE_COREBOOT_TABLE=y
CONFIG_GOOGLE_MEMCONSOLE=y
CONFIG_GOOGLE_MEMCONSOLE_X86_LEGACY=y
CONFIG_GOOGLE_MEMCONSOLE_COREBOOT=y
CONFIG_GOOGLE_VPD=y

#
# EFI (Extensible Firmware Interface) Support
#
CONFIG_EFI_ESRT=y
CONFIG_EFI_VARS_PSTORE=y
CONFIG_EFI_VARS_PSTORE_DEFAULT_DISABLE=y
CONFIG_EFI_RUNTIME_MAP=y
CONFIG_EFI_FAKE_MEMMAP=y
CONFIG_EFI_MAX_FAKE_MEM=8
CONFIG_EFI_SOFT_RESERVE=y
CONFIG_EFI_DXE_MEM_ATTRIBUTES=y
CONFIG_EFI_RUNTIME_WRAPPERS=y
CONFIG_EFI_GENERIC_STUB_INITRD_CMDLINE_LOADER=y
CONFIG_EFI_BOOTLOADER_CONTROL=y
CONFIG_EFI_CAPSULE_LOADER=y
CONFIG_EFI_TEST=y
CONFIG_EFI_DEV_PATH_PARSER=y
CONFIG_APPLE_PROPERTIES=y
CONFIG_RESET_ATTACK_MITIGATION=y
CONFIG_EFI_RCI2_TABLE=y
CONFIG_EFI_DISABLE_PCI_DMA=y
CONFIG_EFI_EARLYCON=y
CONFIG_EFI_CUSTOM_SSDT_OVERLAYS=y
CONFIG_EFI_DISABLE_RUNTIME=y
CONFIG_EFI_COCO_SECRET=y
CONFIG_EFI_EMBEDDED_FIRMWARE=y
# end of EFI (Extensible Firmware Interface) Support

CONFIG_UEFI_CPER=y
CONFIG_UEFI_CPER_X86=y

#
# Tegra firmware driver
#
# end of Tegra firmware driver
# end of Firmware Drivers

CONFIG_GNSS=y
CONFIG_GNSS_SERIAL=y
CONFIG_GNSS_MTK_SERIAL=y
CONFIG_GNSS_SIRF_SERIAL=y
CONFIG_GNSS_UBX_SERIAL=y
CONFIG_GNSS_USB=y
CONFIG_MTD=y
CONFIG_MTD_TESTS=m

#
# Partition parsers
#
CONFIG_MTD_AR7_PARTS=y
CONFIG_MTD_CMDLINE_PARTS=y
CONFIG_MTD_OF_PARTS=y
CONFIG_MTD_REDBOOT_PARTS=y
CONFIG_MTD_REDBOOT_DIRECTORY_BLOCK=-1
CONFIG_MTD_REDBOOT_PARTS_UNALLOCATED=y
CONFIG_MTD_REDBOOT_PARTS_READONLY=y
# end of Partition parsers

#
# User Modules And Translation Layers
#
CONFIG_MTD_BLKDEVS=y
CONFIG_MTD_BLOCK=y

#
# Note that in some cases UBI block is preferred. See MTD_UBI_BLOCK.
#
CONFIG_FTL=y
CONFIG_NFTL=y
CONFIG_NFTL_RW=y
CONFIG_INFTL=y
CONFIG_RFD_FTL=y
CONFIG_SSFDC=y
CONFIG_SM_FTL=y
CONFIG_MTD_OOPS=y
CONFIG_MTD_PSTORE=y
CONFIG_MTD_SWAP=y
CONFIG_MTD_PARTITIONED_MASTER=y

#
# RAM/ROM/Flash chip drivers
#
CONFIG_MTD_CFI=y
CONFIG_MTD_JEDECPROBE=y
CONFIG_MTD_GEN_PROBE=y
CONFIG_MTD_CFI_ADV_OPTIONS=y
CONFIG_MTD_CFI_NOSWAP=y
# CONFIG_MTD_CFI_BE_BYTE_SWAP is not set
# CONFIG_MTD_CFI_LE_BYTE_SWAP is not set
CONFIG_MTD_CFI_GEOMETRY=y
CONFIG_MTD_MAP_BANK_WIDTH_1=y
CONFIG_MTD_MAP_BANK_WIDTH_2=y
CONFIG_MTD_MAP_BANK_WIDTH_4=y
CONFIG_MTD_MAP_BANK_WIDTH_8=y
CONFIG_MTD_MAP_BANK_WIDTH_16=y
CONFIG_MTD_MAP_BANK_WIDTH_32=y
CONFIG_MTD_CFI_I1=y
CONFIG_MTD_CFI_I2=y
CONFIG_MTD_CFI_I4=y
CONFIG_MTD_CFI_I8=y
CONFIG_MTD_OTP=y
CONFIG_MTD_CFI_INTELEXT=y
CONFIG_MTD_CFI_AMDSTD=y
CONFIG_MTD_CFI_STAA=y
CONFIG_MTD_CFI_UTIL=y
CONFIG_MTD_RAM=y
CONFIG_MTD_ROM=y
CONFIG_MTD_ABSENT=y
# end of RAM/ROM/Flash chip drivers

#
# Mapping drivers for chip access
#
CONFIG_MTD_COMPLEX_MAPPINGS=y
CONFIG_MTD_PHYSMAP=y
CONFIG_MTD_PHYSMAP_COMPAT=y
CONFIG_MTD_PHYSMAP_START=0x8000000
CONFIG_MTD_PHYSMAP_LEN=0
CONFIG_MTD_PHYSMAP_BANKWIDTH=2
CONFIG_MTD_PHYSMAP_OF=y
CONFIG_MTD_PHYSMAP_VERSATILE=y
CONFIG_MTD_PHYSMAP_GEMINI=y
CONFIG_MTD_PHYSMAP_GPIO_ADDR=y
CONFIG_MTD_SBC_GXX=y
CONFIG_MTD_AMD76XROM=y
CONFIG_MTD_ICHXROM=y
CONFIG_MTD_ESB2ROM=y
CONFIG_MTD_CK804XROM=y
CONFIG_MTD_SCB2_FLASH=y
CONFIG_MTD_NETtel=y
CONFIG_MTD_L440GX=y
CONFIG_MTD_PCI=y
CONFIG_MTD_PCMCIA=y
CONFIG_MTD_PCMCIA_ANONYMOUS=y
CONFIG_MTD_INTEL_VR_NOR=y
CONFIG_MTD_PLATRAM=y
# end of Mapping drivers for chip access

#
# Self-contained MTD device drivers
#
CONFIG_MTD_PMC551=y
CONFIG_MTD_PMC551_BUGFIX=y
CONFIG_MTD_PMC551_DEBUG=y
CONFIG_MTD_DATAFLASH=y
CONFIG_MTD_DATAFLASH_WRITE_VERIFY=y
CONFIG_MTD_DATAFLASH_OTP=y
CONFIG_MTD_MCHP23K256=y
CONFIG_MTD_MCHP48L640=y
CONFIG_MTD_SST25L=y
CONFIG_MTD_SLRAM=y
CONFIG_MTD_PHRAM=y
CONFIG_MTD_MTDRAM=y
CONFIG_MTDRAM_TOTAL_SIZE=4096
CONFIG_MTDRAM_ERASE_SIZE=128
CONFIG_MTD_BLOCK2MTD=y

#
# Disk-On-Chip Device Drivers
#
CONFIG_MTD_DOCG3=y
CONFIG_BCH_CONST_M=14
CONFIG_BCH_CONST_T=4
# end of Self-contained MTD device drivers

#
# NAND
#
CONFIG_MTD_NAND_CORE=y
CONFIG_MTD_ONENAND=y
CONFIG_MTD_ONENAND_VERIFY_WRITE=y
CONFIG_MTD_ONENAND_GENERIC=y
CONFIG_MTD_ONENAND_OTP=y
CONFIG_MTD_ONENAND_2X_PROGRAM=y
CONFIG_MTD_RAW_NAND=y

#
# Raw/parallel NAND flash controllers
#
CONFIG_MTD_NAND_DENALI=y
CONFIG_MTD_NAND_DENALI_PCI=y
CONFIG_MTD_NAND_DENALI_DT=y
CONFIG_MTD_NAND_CAFE=y
CONFIG_MTD_NAND_MXIC=y
CONFIG_MTD_NAND_GPIO=y
CONFIG_MTD_NAND_PLATFORM=y
CONFIG_MTD_NAND_CADENCE=y
CONFIG_MTD_NAND_ARASAN=y
CONFIG_MTD_NAND_INTEL_LGM=y

#
# Misc
#
CONFIG_MTD_SM_COMMON=y
CONFIG_MTD_NAND_NANDSIM=y
CONFIG_MTD_NAND_RICOH=y
CONFIG_MTD_NAND_DISKONCHIP=y
CONFIG_MTD_NAND_DISKONCHIP_PROBE_ADVANCED=y
CONFIG_MTD_NAND_DISKONCHIP_PROBE_ADDRESS=0
CONFIG_MTD_NAND_DISKONCHIP_PROBE_HIGH=y
CONFIG_MTD_NAND_DISKONCHIP_BBTWRITE=y
CONFIG_MTD_SPI_NAND=y

#
# ECC engine support
#
CONFIG_MTD_NAND_ECC=y
CONFIG_MTD_NAND_ECC_SW_HAMMING=y
CONFIG_MTD_NAND_ECC_SW_HAMMING_SMC=y
CONFIG_MTD_NAND_ECC_SW_BCH=y
CONFIG_MTD_NAND_ECC_MXIC=y
# end of ECC engine support
# end of NAND

#
# LPDDR & LPDDR2 PCM memory drivers
#
CONFIG_MTD_LPDDR=y
CONFIG_MTD_QINFO_PROBE=y
# end of LPDDR & LPDDR2 PCM memory drivers

CONFIG_MTD_SPI_NOR=y
CONFIG_MTD_SPI_NOR_USE_4K_SECTORS=y
# CONFIG_MTD_SPI_NOR_SWP_DISABLE is not set
CONFIG_MTD_SPI_NOR_SWP_DISABLE_ON_VOLATILE=y
# CONFIG_MTD_SPI_NOR_SWP_KEEP is not set
CONFIG_MTD_UBI=y
CONFIG_MTD_UBI_WL_THRESHOLD=4096
CONFIG_MTD_UBI_BEB_LIMIT=20
CONFIG_MTD_UBI_FASTMAP=y
CONFIG_MTD_UBI_GLUEBI=y
CONFIG_MTD_UBI_BLOCK=y
CONFIG_MTD_HYPERBUS=y
CONFIG_DTC=y
CONFIG_OF=y
CONFIG_OF_UNITTEST=y
CONFIG_OF_FLATTREE=y
CONFIG_OF_EARLY_FLATTREE=y
CONFIG_OF_KOBJ=y
CONFIG_OF_DYNAMIC=y
CONFIG_OF_ADDRESS=y
CONFIG_OF_IRQ=y
CONFIG_OF_RESERVED_MEM=y
CONFIG_OF_RESOLVE=y
CONFIG_OF_OVERLAY=y
CONFIG_ARCH_MIGHT_HAVE_PC_PARPORT=y
CONFIG_PARPORT=y
CONFIG_PARPORT_PC=y
CONFIG_PARPORT_SERIAL=y
CONFIG_PARPORT_PC_FIFO=y
CONFIG_PARPORT_PC_SUPERIO=y
CONFIG_PARPORT_PC_PCMCIA=y
CONFIG_PARPORT_AX88796=y
CONFIG_PARPORT_1284=y
CONFIG_PARPORT_NOT_PC=y
CONFIG_PNP=y
CONFIG_PNP_DEBUG_MESSAGES=y

#
# Protocols
#
CONFIG_PNPACPI=y
CONFIG_BLK_DEV=y
CONFIG_BLK_DEV_NULL_BLK=y
CONFIG_BLK_DEV_NULL_BLK_FAULT_INJECTION=y
CONFIG_BLK_DEV_FD=y
CONFIG_BLK_DEV_FD_RAWCMD=y
CONFIG_CDROM=y
CONFIG_PARIDE=y

#
# Parallel IDE high-level drivers
#
CONFIG_PARIDE_PD=y
CONFIG_PARIDE_PCD=y
CONFIG_PARIDE_PF=y
CONFIG_PARIDE_PT=y
CONFIG_PARIDE_PG=y

#
# Parallel IDE protocol modules
#
CONFIG_PARIDE_ATEN=y
CONFIG_PARIDE_BPCK=y
CONFIG_PARIDE_COMM=y
CONFIG_PARIDE_DSTR=y
CONFIG_PARIDE_FIT2=y
CONFIG_PARIDE_FIT3=y
CONFIG_PARIDE_EPAT=y
CONFIG_PARIDE_EPATC8=y
CONFIG_PARIDE_EPIA=y
CONFIG_PARIDE_FRIQ=y
CONFIG_PARIDE_FRPW=y
CONFIG_PARIDE_KBIC=y
CONFIG_PARIDE_KTTI=y
CONFIG_PARIDE_ON20=y
CONFIG_PARIDE_ON26=y
CONFIG_BLK_DEV_PCIESSD_MTIP32XX=y
CONFIG_ZRAM=y
CONFIG_ZRAM_DEF_COMP_LZORLE=y
# CONFIG_ZRAM_DEF_COMP_ZSTD is not set
# CONFIG_ZRAM_DEF_COMP_LZ4 is not set
# CONFIG_ZRAM_DEF_COMP_LZO is not set
# CONFIG_ZRAM_DEF_COMP_LZ4HC is not set
# CONFIG_ZRAM_DEF_COMP_842 is not set
CONFIG_ZRAM_DEF_COMP="lzo-rle"
CONFIG_ZRAM_WRITEBACK=y
CONFIG_ZRAM_MEMORY_TRACKING=y
CONFIG_BLK_DEV_LOOP=y
CONFIG_BLK_DEV_LOOP_MIN_COUNT=8
CONFIG_BLK_DEV_DRBD=y
CONFIG_DRBD_FAULT_INJECTION=y
CONFIG_BLK_DEV_NBD=y
CONFIG_BLK_DEV_RAM=y
CONFIG_BLK_DEV_RAM_COUNT=16
CONFIG_BLK_DEV_RAM_SIZE=4096
CONFIG_CDROM_PKTCDVD=y
CONFIG_CDROM_PKTCDVD_BUFFERS=8
CONFIG_CDROM_PKTCDVD_WCACHE=y
CONFIG_ATA_OVER_ETH=y
CONFIG_XEN_BLKDEV_FRONTEND=y
CONFIG_XEN_BLKDEV_BACKEND=y
CONFIG_VIRTIO_BLK=y
CONFIG_BLK_DEV_RBD=y
CONFIG_BLK_DEV_UBLK=y
CONFIG_BLK_DEV_RNBD=y
CONFIG_BLK_DEV_RNBD_CLIENT=y
CONFIG_BLK_DEV_RNBD_SERVER=y

#
# NVME Support
#
CONFIG_NVME_COMMON=y
CONFIG_NVME_CORE=y
CONFIG_BLK_DEV_NVME=y
CONFIG_NVME_MULTIPATH=y
CONFIG_NVME_VERBOSE_ERRORS=y
CONFIG_NVME_HWMON=y
CONFIG_NVME_FABRICS=y
CONFIG_NVME_RDMA=y
CONFIG_NVME_FC=y
CONFIG_NVME_TCP=y
CONFIG_NVME_AUTH=y
CONFIG_NVME_TARGET=y
CONFIG_NVME_TARGET_PASSTHRU=y
CONFIG_NVME_TARGET_LOOP=y
CONFIG_NVME_TARGET_RDMA=y
CONFIG_NVME_TARGET_FC=y
CONFIG_NVME_TARGET_FCLOOP=y
CONFIG_NVME_TARGET_TCP=y
CONFIG_NVME_TARGET_AUTH=y
# end of NVME Support

#
# Misc devices
#
CONFIG_SENSORS_LIS3LV02D=y
CONFIG_AD525X_DPOT=y
CONFIG_AD525X_DPOT_I2C=y
CONFIG_AD525X_DPOT_SPI=y
CONFIG_DUMMY_IRQ=y
CONFIG_IBM_ASM=y
CONFIG_PHANTOM=y
CONFIG_TIFM_CORE=y
CONFIG_TIFM_7XX1=y
CONFIG_ICS932S401=y
CONFIG_ENCLOSURE_SERVICES=y
CONFIG_SGI_XP=y
CONFIG_HI6421V600_IRQ=y
CONFIG_HP_ILO=y
CONFIG_SGI_GRU=y
CONFIG_SGI_GRU_DEBUG=y
CONFIG_APDS9802ALS=y
CONFIG_ISL29003=y
CONFIG_ISL29020=y
CONFIG_SENSORS_TSL2550=y
CONFIG_SENSORS_BH1770=y
CONFIG_SENSORS_APDS990X=y
CONFIG_HMC6352=y
CONFIG_DS1682=y
CONFIG_VMWARE_BALLOON=y
CONFIG_LATTICE_ECP3_CONFIG=y
CONFIG_SRAM=y
CONFIG_DW_XDATA_PCIE=y
CONFIG_PCI_ENDPOINT_TEST=y
CONFIG_XILINX_SDFEC=y
CONFIG_MISC_RTSX=y
CONFIG_HISI_HIKEY_USB=y
CONFIG_OPEN_DICE=y
CONFIG_VCPU_STALL_DETECTOR=y
CONFIG_C2PORT=y
CONFIG_C2PORT_DURAMAR_2150=y

#
# EEPROM support
#
CONFIG_EEPROM_AT24=y
CONFIG_EEPROM_AT25=y
CONFIG_EEPROM_LEGACY=y
CONFIG_EEPROM_MAX6875=y
CONFIG_EEPROM_93CX6=y
CONFIG_EEPROM_93XX46=y
CONFIG_EEPROM_IDT_89HPESX=y
CONFIG_EEPROM_EE1004=y
# end of EEPROM support

CONFIG_CB710_CORE=y
CONFIG_CB710_DEBUG=y
CONFIG_CB710_DEBUG_ASSUMPTIONS=y

#
# Texas Instruments shared transport line discipline
#
CONFIG_TI_ST=y
# end of Texas Instruments shared transport line discipline

CONFIG_SENSORS_LIS3_I2C=y
CONFIG_ALTERA_STAPL=y
CONFIG_INTEL_MEI=y
CONFIG_INTEL_MEI_ME=y
CONFIG_INTEL_MEI_TXE=y
CONFIG_INTEL_MEI_GSC=y
CONFIG_INTEL_MEI_HDCP=y
CONFIG_INTEL_MEI_PXP=y
CONFIG_VMWARE_VMCI=y
CONFIG_GENWQE=y
CONFIG_GENWQE_PLATFORM_ERROR_RECOVERY=0
CONFIG_ECHO=y
CONFIG_BCM_VK=y
CONFIG_BCM_VK_TTY=y
CONFIG_MISC_ALCOR_PCI=y
CONFIG_MISC_RTSX_PCI=y
CONFIG_MISC_RTSX_USB=y
CONFIG_HABANA_AI=y
CONFIG_UACCE=y
CONFIG_PVPANIC=y
CONFIG_PVPANIC_MMIO=y
CONFIG_PVPANIC_PCI=y
# end of Misc devices

#
# SCSI device support
#
CONFIG_SCSI_MOD=y
CONFIG_RAID_ATTRS=y
CONFIG_SCSI_COMMON=y
CONFIG_SCSI=y
CONFIG_SCSI_DMA=y
CONFIG_SCSI_NETLINK=y
CONFIG_SCSI_PROC_FS=y

#
# SCSI support type (disk, tape, CD-ROM)
#
CONFIG_BLK_DEV_SD=y
CONFIG_CHR_DEV_ST=y
CONFIG_BLK_DEV_SR=y
CONFIG_CHR_DEV_SG=y
CONFIG_BLK_DEV_BSG=y
CONFIG_CHR_DEV_SCH=y
CONFIG_SCSI_ENCLOSURE=y
CONFIG_SCSI_CONSTANTS=y
CONFIG_SCSI_LOGGING=y
CONFIG_SCSI_SCAN_ASYNC=y

#
# SCSI Transports
#
CONFIG_SCSI_SPI_ATTRS=y
CONFIG_SCSI_FC_ATTRS=y
CONFIG_SCSI_ISCSI_ATTRS=y
CONFIG_SCSI_SAS_ATTRS=y
CONFIG_SCSI_SAS_LIBSAS=y
CONFIG_SCSI_SAS_ATA=y
CONFIG_SCSI_SAS_HOST_SMP=y
CONFIG_SCSI_SRP_ATTRS=y
# end of SCSI Transports

CONFIG_SCSI_LOWLEVEL=y
CONFIG_ISCSI_TCP=y
CONFIG_ISCSI_BOOT_SYSFS=y
CONFIG_SCSI_CXGB3_ISCSI=y
CONFIG_SCSI_CXGB4_ISCSI=y
CONFIG_SCSI_BNX2_ISCSI=y
CONFIG_SCSI_BNX2X_FCOE=y
CONFIG_BE2ISCSI=y
CONFIG_BLK_DEV_3W_XXXX_RAID=y
CONFIG_SCSI_HPSA=y
CONFIG_SCSI_3W_9XXX=y
CONFIG_SCSI_3W_SAS=y
CONFIG_SCSI_ACARD=y
CONFIG_SCSI_AHA1740=y
CONFIG_SCSI_AACRAID=y
CONFIG_SCSI_AIC7XXX=y
CONFIG_AIC7XXX_CMDS_PER_DEVICE=32
CONFIG_AIC7XXX_RESET_DELAY_MS=5000
CONFIG_AIC7XXX_DEBUG_ENABLE=y
CONFIG_AIC7XXX_DEBUG_MASK=0
CONFIG_AIC7XXX_REG_PRETTY_PRINT=y
CONFIG_SCSI_AIC79XX=y
CONFIG_AIC79XX_CMDS_PER_DEVICE=32
CONFIG_AIC79XX_RESET_DELAY_MS=5000
CONFIG_AIC79XX_DEBUG_ENABLE=y
CONFIG_AIC79XX_DEBUG_MASK=0
CONFIG_AIC79XX_REG_PRETTY_PRINT=y
CONFIG_SCSI_AIC94XX=y
CONFIG_AIC94XX_DEBUG=y
CONFIG_SCSI_MVSAS=y
CONFIG_SCSI_MVSAS_DEBUG=y
CONFIG_SCSI_MVSAS_TASKLET=y
CONFIG_SCSI_MVUMI=y
CONFIG_SCSI_ADVANSYS=y
CONFIG_SCSI_ARCMSR=y
CONFIG_SCSI_ESAS2R=y
CONFIG_MEGARAID_NEWGEN=y
CONFIG_MEGARAID_MM=y
CONFIG_MEGARAID_MAILBOX=y
CONFIG_MEGARAID_LEGACY=y
CONFIG_MEGARAID_SAS=y
CONFIG_SCSI_MPT3SAS=y
CONFIG_SCSI_MPT2SAS_MAX_SGE=128
CONFIG_SCSI_MPT3SAS_MAX_SGE=128
CONFIG_SCSI_MPT2SAS=y
CONFIG_SCSI_MPI3MR=y
CONFIG_SCSI_SMARTPQI=y
CONFIG_SCSI_HPTIOP=y
CONFIG_SCSI_BUSLOGIC=y
CONFIG_SCSI_FLASHPOINT=y
CONFIG_SCSI_MYRB=y
CONFIG_SCSI_MYRS=y
CONFIG_VMWARE_PVSCSI=y
CONFIG_XEN_SCSI_FRONTEND=y
CONFIG_HYPERV_STORAGE=y
CONFIG_LIBFC=y
CONFIG_LIBFCOE=y
CONFIG_FCOE=y
CONFIG_FCOE_FNIC=y
CONFIG_SCSI_SNIC=y
CONFIG_SCSI_SNIC_DEBUG_FS=y
CONFIG_SCSI_DMX3191D=y
CONFIG_SCSI_FDOMAIN=y
CONFIG_SCSI_FDOMAIN_PCI=y
CONFIG_SCSI_ISCI=y
CONFIG_SCSI_IPS=y
CONFIG_SCSI_INITIO=y
CONFIG_SCSI_INIA100=y
CONFIG_SCSI_PPA=y
CONFIG_SCSI_IMM=y
CONFIG_SCSI_IZIP_EPP16=y
CONFIG_SCSI_IZIP_SLOW_CTR=y
CONFIG_SCSI_STEX=y
CONFIG_SCSI_SYM53C8XX_2=y
CONFIG_SCSI_SYM53C8XX_DMA_ADDRESSING_MODE=1
CONFIG_SCSI_SYM53C8XX_DEFAULT_TAGS=16
CONFIG_SCSI_SYM53C8XX_MAX_TAGS=64
CONFIG_SCSI_SYM53C8XX_MMIO=y
CONFIG_SCSI_IPR=y
CONFIG_SCSI_IPR_TRACE=y
CONFIG_SCSI_IPR_DUMP=y
CONFIG_SCSI_QLOGIC_1280=y
CONFIG_SCSI_QLA_FC=y
CONFIG_TCM_QLA2XXX=y
CONFIG_TCM_QLA2XXX_DEBUG=y
CONFIG_SCSI_QLA_ISCSI=y
CONFIG_QEDI=y
CONFIG_QEDF=y
CONFIG_SCSI_LPFC=y
CONFIG_SCSI_LPFC_DEBUG_FS=y
CONFIG_SCSI_EFCT=y
CONFIG_SCSI_SIM710=y
CONFIG_SCSI_DC395x=y
CONFIG_SCSI_AM53C974=y
CONFIG_SCSI_WD719X=y
CONFIG_SCSI_DEBUG=y
CONFIG_SCSI_PMCRAID=y
CONFIG_SCSI_PM8001=y
CONFIG_SCSI_BFA_FC=y
CONFIG_SCSI_VIRTIO=y
CONFIG_SCSI_CHELSIO_FCOE=y
CONFIG_SCSI_LOWLEVEL_PCMCIA=y
CONFIG_PCMCIA_AHA152X=m
CONFIG_PCMCIA_FDOMAIN=m
CONFIG_PCMCIA_QLOGIC=m
CONFIG_PCMCIA_SYM53C500=m
CONFIG_SCSI_DH=y
CONFIG_SCSI_DH_RDAC=y
CONFIG_SCSI_DH_HP_SW=y
CONFIG_SCSI_DH_EMC=y
CONFIG_SCSI_DH_ALUA=y
# end of SCSI device support

CONFIG_ATA=y
CONFIG_SATA_HOST=y
CONFIG_PATA_TIMINGS=y
CONFIG_ATA_VERBOSE_ERROR=y
CONFIG_ATA_FORCE=y
CONFIG_ATA_ACPI=y
CONFIG_SATA_ZPODD=y
CONFIG_SATA_PMP=y

#
# Controllers with non-SFF native interface
#
CONFIG_SATA_AHCI=y
CONFIG_SATA_MOBILE_LPM_POLICY=0
CONFIG_SATA_AHCI_PLATFORM=y
CONFIG_AHCI_CEVA=y
CONFIG_AHCI_QORIQ=y
CONFIG_SATA_INIC162X=y
CONFIG_SATA_ACARD_AHCI=y
CONFIG_SATA_SIL24=y
CONFIG_ATA_SFF=y

#
# SFF controllers with custom DMA interface
#
CONFIG_PDC_ADMA=y
CONFIG_SATA_QSTOR=y
CONFIG_SATA_SX4=y
CONFIG_ATA_BMDMA=y

#
# SATA SFF controllers with BMDMA
#
CONFIG_ATA_PIIX=y
CONFIG_SATA_DWC=y
CONFIG_SATA_DWC_OLD_DMA=y
CONFIG_SATA_MV=y
CONFIG_SATA_NV=y
CONFIG_SATA_PROMISE=y
CONFIG_SATA_SIL=y
CONFIG_SATA_SIS=y
CONFIG_SATA_SVW=y
CONFIG_SATA_ULI=y
CONFIG_SATA_VIA=y
CONFIG_SATA_VITESSE=y

#
# PATA SFF controllers with BMDMA
#
CONFIG_PATA_ALI=y
CONFIG_PATA_AMD=y
CONFIG_PATA_ARTOP=y
CONFIG_PATA_ATIIXP=y
CONFIG_PATA_ATP867X=y
CONFIG_PATA_CMD64X=y
CONFIG_PATA_CYPRESS=y
CONFIG_PATA_EFAR=y
CONFIG_PATA_HPT366=y
CONFIG_PATA_HPT37X=y
CONFIG_PATA_HPT3X2N=y
CONFIG_PATA_HPT3X3=y
CONFIG_PATA_HPT3X3_DMA=y
CONFIG_PATA_IT8213=y
CONFIG_PATA_IT821X=y
CONFIG_PATA_JMICRON=y
CONFIG_PATA_MARVELL=y
CONFIG_PATA_NETCELL=y
CONFIG_PATA_NINJA32=y
CONFIG_PATA_NS87415=y
CONFIG_PATA_OLDPIIX=y
CONFIG_PATA_OPTIDMA=y
CONFIG_PATA_PDC2027X=y
CONFIG_PATA_PDC_OLD=y
CONFIG_PATA_RADISYS=y
CONFIG_PATA_RDC=y
CONFIG_PATA_SCH=y
CONFIG_PATA_SERVERWORKS=y
CONFIG_PATA_SIL680=y
CONFIG_PATA_SIS=y
CONFIG_PATA_TOSHIBA=y
CONFIG_PATA_TRIFLEX=y
CONFIG_PATA_VIA=y
CONFIG_PATA_WINBOND=y

#
# PIO-only SFF controllers
#
CONFIG_PATA_CMD640_PCI=y
CONFIG_PATA_MPIIX=y
CONFIG_PATA_NS87410=y
CONFIG_PATA_OPTI=y
CONFIG_PATA_PCMCIA=y
CONFIG_PATA_PLATFORM=y
CONFIG_PATA_OF_PLATFORM=y
CONFIG_PATA_RZ1000=y

#
# Generic fallback / legacy drivers
#
CONFIG_PATA_ACPI=y
CONFIG_ATA_GENERIC=y
CONFIG_PATA_LEGACY=y
CONFIG_MD=y
CONFIG_BLK_DEV_MD=y
CONFIG_MD_AUTODETECT=y
CONFIG_MD_LINEAR=y
CONFIG_MD_RAID0=y
CONFIG_MD_RAID1=y
CONFIG_MD_RAID10=y
CONFIG_MD_RAID456=y
CONFIG_MD_MULTIPATH=y
CONFIG_MD_FAULTY=y
CONFIG_MD_CLUSTER=y
CONFIG_BCACHE=y
CONFIG_BCACHE_DEBUG=y
CONFIG_BCACHE_CLOSURES_DEBUG=y
CONFIG_BCACHE_ASYNC_REGISTRATION=y
CONFIG_BLK_DEV_DM_BUILTIN=y
CONFIG_BLK_DEV_DM=y
CONFIG_DM_DEBUG=y
CONFIG_DM_BUFIO=y
CONFIG_DM_DEBUG_BLOCK_MANAGER_LOCKING=y
CONFIG_DM_DEBUG_BLOCK_STACK_TRACING=y
CONFIG_DM_BIO_PRISON=y
CONFIG_DM_PERSISTENT_DATA=y
CONFIG_DM_UNSTRIPED=y
CONFIG_DM_CRYPT=y
CONFIG_DM_SNAPSHOT=y
CONFIG_DM_THIN_PROVISIONING=y
CONFIG_DM_CACHE=y
CONFIG_DM_CACHE_SMQ=y
CONFIG_DM_WRITECACHE=y
CONFIG_DM_EBS=y
CONFIG_DM_ERA=y
CONFIG_DM_CLONE=y
CONFIG_DM_MIRROR=y
CONFIG_DM_LOG_USERSPACE=y
CONFIG_DM_RAID=y
CONFIG_DM_ZERO=y
CONFIG_DM_MULTIPATH=y
CONFIG_DM_MULTIPATH_QL=y
CONFIG_DM_MULTIPATH_ST=y
CONFIG_DM_MULTIPATH_HST=y
CONFIG_DM_MULTIPATH_IOA=y
CONFIG_DM_DELAY=y
CONFIG_DM_DUST=y
CONFIG_DM_INIT=y
CONFIG_DM_UEVENT=y
CONFIG_DM_FLAKEY=y
CONFIG_DM_VERITY=y
CONFIG_DM_VERITY_VERIFY_ROOTHASH_SIG=y
CONFIG_DM_VERITY_VERIFY_ROOTHASH_SIG_SECONDARY_KEYRING=y
CONFIG_DM_VERITY_FEC=y
CONFIG_DM_SWITCH=y
CONFIG_DM_LOG_WRITES=y
CONFIG_DM_INTEGRITY=y
CONFIG_DM_ZONED=y
CONFIG_DM_AUDIT=y
CONFIG_TARGET_CORE=y
CONFIG_TCM_IBLOCK=y
CONFIG_TCM_FILEIO=y
CONFIG_TCM_PSCSI=y
CONFIG_TCM_USER2=y
CONFIG_LOOPBACK_TARGET=y
CONFIG_TCM_FC=y
CONFIG_ISCSI_TARGET=y
CONFIG_ISCSI_TARGET_CXGB4=y
CONFIG_SBP_TARGET=y
CONFIG_FUSION=y
CONFIG_FUSION_SPI=y
CONFIG_FUSION_FC=y
CONFIG_FUSION_SAS=y
CONFIG_FUSION_MAX_SGE=128
CONFIG_FUSION_CTL=y
CONFIG_FUSION_LAN=y
CONFIG_FUSION_LOGGING=y

#
# IEEE 1394 (FireWire) support
#
CONFIG_FIREWIRE=y
CONFIG_FIREWIRE_OHCI=y
CONFIG_FIREWIRE_SBP2=y
CONFIG_FIREWIRE_NET=y
CONFIG_FIREWIRE_NOSY=y
# end of IEEE 1394 (FireWire) support

CONFIG_MACINTOSH_DRIVERS=y
CONFIG_MAC_EMUMOUSEBTN=y
CONFIG_NETDEVICES=y
CONFIG_MII=y
CONFIG_NET_CORE=y
CONFIG_BONDING=y
CONFIG_DUMMY=y
CONFIG_WIREGUARD=y
CONFIG_WIREGUARD_DEBUG=y
CONFIG_EQUALIZER=y
CONFIG_NET_FC=y
CONFIG_IFB=y
CONFIG_NET_TEAM=y
CONFIG_NET_TEAM_MODE_BROADCAST=y
CONFIG_NET_TEAM_MODE_ROUNDROBIN=y
CONFIG_NET_TEAM_MODE_RANDOM=y
CONFIG_NET_TEAM_MODE_ACTIVEBACKUP=y
CONFIG_NET_TEAM_MODE_LOADBALANCE=y
CONFIG_MACVLAN=y
CONFIG_MACVTAP=y
CONFIG_IPVLAN_L3S=y
CONFIG_IPVLAN=y
CONFIG_IPVTAP=y
CONFIG_VXLAN=y
CONFIG_GENEVE=y
CONFIG_BAREUDP=y
CONFIG_GTP=y
CONFIG_AMT=y
CONFIG_MACSEC=y
CONFIG_NETCONSOLE=y
CONFIG_NETCONSOLE_DYNAMIC=y
CONFIG_NETPOLL=y
CONFIG_NET_POLL_CONTROLLER=y
CONFIG_NTB_NETDEV=y
CONFIG_RIONET=y
CONFIG_RIONET_TX_SIZE=128
CONFIG_RIONET_RX_SIZE=128
CONFIG_TUN=y
CONFIG_TAP=y
CONFIG_TUN_VNET_CROSS_LE=y
CONFIG_VETH=y
CONFIG_VIRTIO_NET=y
CONFIG_NLMON=y
CONFIG_NET_VRF=y
CONFIG_VSOCKMON=y
CONFIG_MHI_NET=y
CONFIG_SUNGEM_PHY=y
CONFIG_ARCNET=y
CONFIG_ARCNET_1201=y
CONFIG_ARCNET_1051=y
CONFIG_ARCNET_RAW=y
CONFIG_ARCNET_CAP=y
CONFIG_ARCNET_COM90xx=y
CONFIG_ARCNET_COM90xxIO=y
CONFIG_ARCNET_RIM_I=y
CONFIG_ARCNET_COM20020=y
CONFIG_ARCNET_COM20020_PCI=y
CONFIG_ARCNET_COM20020_CS=y
CONFIG_ATM_DRIVERS=y
CONFIG_ATM_DUMMY=y
CONFIG_ATM_TCP=y
CONFIG_ATM_LANAI=y
CONFIG_ATM_ENI=y
CONFIG_ATM_ENI_DEBUG=y
CONFIG_ATM_ENI_TUNE_BURST=y
CONFIG_ATM_ENI_BURST_TX_16W=y
CONFIG_ATM_ENI_BURST_TX_8W=y
CONFIG_ATM_ENI_BURST_TX_4W=y
CONFIG_ATM_ENI_BURST_TX_2W=y
CONFIG_ATM_ENI_BURST_RX_16W=y
CONFIG_ATM_ENI_BURST_RX_8W=y
CONFIG_ATM_ENI_BURST_RX_4W=y
CONFIG_ATM_ENI_BURST_RX_2W=y
CONFIG_ATM_NICSTAR=y
CONFIG_ATM_NICSTAR_USE_SUNI=y
CONFIG_ATM_NICSTAR_USE_IDT77105=y
CONFIG_ATM_IDT77252=y
CONFIG_ATM_IDT77252_DEBUG=y
CONFIG_ATM_IDT77252_RCV_ALL=y
CONFIG_ATM_IDT77252_USE_SUNI=y
CONFIG_ATM_IA=y
CONFIG_ATM_IA_DEBUG=y
CONFIG_ATM_FORE200E=y
CONFIG_ATM_FORE200E_USE_TASKLET=y
CONFIG_ATM_FORE200E_TX_RETRY=16
CONFIG_ATM_FORE200E_DEBUG=0
CONFIG_ATM_HE=y
CONFIG_ATM_HE_USE_SUNI=y
CONFIG_ATM_SOLOS=y
CONFIG_CAIF_DRIVERS=y
CONFIG_CAIF_TTY=y
CONFIG_CAIF_VIRTIO=y

#
# Distributed Switch Architecture drivers
#
CONFIG_B53=y
CONFIG_B53_SPI_DRIVER=y
CONFIG_B53_MDIO_DRIVER=y
CONFIG_B53_MMAP_DRIVER=y
CONFIG_B53_SRAB_DRIVER=y
CONFIG_B53_SERDES=y
CONFIG_NET_DSA_BCM_SF2=y
CONFIG_NET_DSA_LOOP=y
CONFIG_NET_DSA_HIRSCHMANN_HELLCREEK=y
CONFIG_NET_DSA_LANTIQ_GSWIP=y
CONFIG_NET_DSA_MT7530=y
CONFIG_NET_DSA_MV88E6060=y
CONFIG_NET_DSA_MICROCHIP_KSZ_COMMON=y
CONFIG_NET_DSA_MICROCHIP_KSZ9477_I2C=y
CONFIG_NET_DSA_MICROCHIP_KSZ_SPI=y
CONFIG_NET_DSA_MICROCHIP_KSZ8863_SMI=y
CONFIG_NET_DSA_MV88E6XXX=y
CONFIG_NET_DSA_MV88E6XXX_PTP=y
CONFIG_NET_DSA_MSCC_SEVILLE=y
CONFIG_NET_DSA_AR9331=y
CONFIG_NET_DSA_QCA8K=y
CONFIG_NET_DSA_SJA1105=y
CONFIG_NET_DSA_SJA1105_PTP=y
CONFIG_NET_DSA_SJA1105_TAS=y
CONFIG_NET_DSA_SJA1105_VL=y
CONFIG_NET_DSA_XRS700X=y
CONFIG_NET_DSA_XRS700X_I2C=y
CONFIG_NET_DSA_XRS700X_MDIO=y
CONFIG_NET_DSA_REALTEK=y
CONFIG_NET_DSA_REALTEK_MDIO=y
CONFIG_NET_DSA_REALTEK_SMI=y
CONFIG_NET_DSA_REALTEK_RTL8365MB=y
CONFIG_NET_DSA_REALTEK_RTL8366RB=y
CONFIG_NET_DSA_SMSC_LAN9303=y
CONFIG_NET_DSA_SMSC_LAN9303_I2C=y
CONFIG_NET_DSA_SMSC_LAN9303_MDIO=y
CONFIG_NET_DSA_VITESSE_VSC73XX=y
CONFIG_NET_DSA_VITESSE_VSC73XX_SPI=y
CONFIG_NET_DSA_VITESSE_VSC73XX_PLATFORM=y
# end of Distributed Switch Architecture drivers

CONFIG_ETHERNET=y
CONFIG_MDIO=y
CONFIG_NET_VENDOR_3COM=y
CONFIG_EL3=y
CONFIG_PCMCIA_3C574=y
CONFIG_PCMCIA_3C589=y
CONFIG_VORTEX=y
CONFIG_TYPHOON=y
CONFIG_NET_VENDOR_ADAPTEC=y
CONFIG_ADAPTEC_STARFIRE=y
CONFIG_NET_VENDOR_AGERE=y
CONFIG_ET131X=y
CONFIG_NET_VENDOR_ALACRITECH=y
CONFIG_SLICOSS=y
CONFIG_NET_VENDOR_ALTEON=y
CONFIG_ACENIC=y
CONFIG_ACENIC_OMIT_TIGON_I=y
CONFIG_ALTERA_TSE=y
CONFIG_NET_VENDOR_AMAZON=y
CONFIG_ENA_ETHERNET=y
CONFIG_NET_VENDOR_AMD=y
CONFIG_AMD8111_ETH=y
CONFIG_PCNET32=y
CONFIG_PCMCIA_NMCLAN=y
CONFIG_AMD_XGBE=y
CONFIG_AMD_XGBE_DCB=y
CONFIG_AMD_XGBE_HAVE_ECC=y
CONFIG_NET_VENDOR_AQUANTIA=y
CONFIG_AQTION=y
CONFIG_NET_VENDOR_ARC=y
CONFIG_NET_VENDOR_ASIX=y
CONFIG_SPI_AX88796C=y
CONFIG_SPI_AX88796C_COMPRESSION=y
CONFIG_NET_VENDOR_ATHEROS=y
CONFIG_ATL2=y
CONFIG_ATL1=y
CONFIG_ATL1E=y
CONFIG_ATL1C=y
CONFIG_ALX=y
CONFIG_CX_ECAT=y
CONFIG_NET_VENDOR_BROADCOM=y
CONFIG_B44=y
CONFIG_B44_PCI_AUTOSELECT=y
CONFIG_B44_PCICORE_AUTOSELECT=y
CONFIG_B44_PCI=y
CONFIG_BCMGENET=y
CONFIG_BNX2=y
CONFIG_CNIC=y
CONFIG_TIGON3=y
CONFIG_TIGON3_HWMON=y
CONFIG_BNX2X=y
CONFIG_BNX2X_SRIOV=y
CONFIG_SYSTEMPORT=y
CONFIG_BNXT=y
CONFIG_BNXT_SRIOV=y
CONFIG_BNXT_FLOWER_OFFLOAD=y
CONFIG_BNXT_DCB=y
CONFIG_BNXT_HWMON=y
CONFIG_NET_VENDOR_CADENCE=y
CONFIG_MACB=y
CONFIG_MACB_USE_HWSTAMP=y
CONFIG_MACB_PCI=y
CONFIG_NET_VENDOR_CAVIUM=y
CONFIG_THUNDER_NIC_PF=y
CONFIG_THUNDER_NIC_VF=y
CONFIG_THUNDER_NIC_BGX=y
CONFIG_THUNDER_NIC_RGX=y
CONFIG_CAVIUM_PTP=y
CONFIG_LIQUIDIO=y
CONFIG_LIQUIDIO_VF=y
CONFIG_NET_VENDOR_CHELSIO=y
CONFIG_CHELSIO_T1=y
CONFIG_CHELSIO_T1_1G=y
CONFIG_CHELSIO_T3=y
CONFIG_CHELSIO_T4=y
CONFIG_CHELSIO_T4_DCB=y
CONFIG_CHELSIO_T4_FCOE=y
CONFIG_CHELSIO_T4VF=y
CONFIG_CHELSIO_LIB=y
CONFIG_CHELSIO_INLINE_CRYPTO=y
CONFIG_CRYPTO_DEV_CHELSIO_TLS=y
CONFIG_CHELSIO_IPSEC_INLINE=y
CONFIG_CHELSIO_TLS_DEVICE=y
CONFIG_NET_VENDOR_CIRRUS=y
CONFIG_NET_VENDOR_CISCO=y
CONFIG_ENIC=y
CONFIG_NET_VENDOR_CORTINA=y
CONFIG_GEMINI_ETHERNET=y
CONFIG_NET_VENDOR_DAVICOM=y
CONFIG_DM9051=y
CONFIG_DNET=y
CONFIG_NET_VENDOR_DEC=y
CONFIG_NET_TULIP=y
CONFIG_DE2104X=y
CONFIG_DE2104X_DSL=0
CONFIG_TULIP=y
CONFIG_TULIP_MWI=y
CONFIG_TULIP_MMIO=y
CONFIG_TULIP_NAPI=y
CONFIG_TULIP_NAPI_HW_MITIGATION=y
CONFIG_WINBOND_840=y
CONFIG_DM9102=y
CONFIG_ULI526X=y
CONFIG_PCMCIA_XIRCOM=y
CONFIG_NET_VENDOR_DLINK=y
CONFIG_DL2K=y
CONFIG_SUNDANCE=y
CONFIG_SUNDANCE_MMIO=y
CONFIG_NET_VENDOR_EMULEX=y
CONFIG_BE2NET=y
CONFIG_BE2NET_HWMON=y
CONFIG_BE2NET_BE2=y
CONFIG_BE2NET_BE3=y
CONFIG_BE2NET_LANCER=y
CONFIG_BE2NET_SKYHAWK=y
CONFIG_NET_VENDOR_ENGLEDER=y
CONFIG_TSNEP=y
CONFIG_TSNEP_SELFTESTS=y
CONFIG_NET_VENDOR_EZCHIP=y
CONFIG_EZCHIP_NPS_MANAGEMENT_ENET=y
CONFIG_NET_VENDOR_FUJITSU=y
CONFIG_PCMCIA_FMVJ18X=y
CONFIG_NET_VENDOR_FUNGIBLE=y
CONFIG_FUN_CORE=y
CONFIG_FUN_ETH=y
CONFIG_NET_VENDOR_GOOGLE=y
CONFIG_GVE=y
CONFIG_NET_VENDOR_HUAWEI=y
CONFIG_HINIC=y
CONFIG_NET_VENDOR_I825XX=y
CONFIG_NET_VENDOR_INTEL=y
CONFIG_E100=y
CONFIG_E1000=y
CONFIG_E1000E=y
CONFIG_E1000E_HWTS=y
CONFIG_IGB=y
CONFIG_IGB_HWMON=y
CONFIG_IGB_DCA=y
CONFIG_IGBVF=y
CONFIG_IXGB=y
CONFIG_IXGBE=y
CONFIG_IXGBE_HWMON=y
CONFIG_IXGBE_DCA=y
CONFIG_IXGBE_DCB=y
CONFIG_IXGBE_IPSEC=y
CONFIG_IXGBEVF=y
CONFIG_IXGBEVF_IPSEC=y
CONFIG_I40E=y
CONFIG_I40E_DCB=y
CONFIG_IAVF=y
CONFIG_I40EVF=y
CONFIG_ICE=y
CONFIG_ICE_SWITCHDEV=y
CONFIG_ICE_HWTS=y
CONFIG_FM10K=y
CONFIG_IGC=y
CONFIG_NET_VENDOR_WANGXUN=y
CONFIG_TXGBE=y
CONFIG_JME=y
CONFIG_NET_VENDOR_LITEX=y
CONFIG_LITEX_LITEETH=y
CONFIG_NET_VENDOR_MARVELL=y
CONFIG_MVMDIO=y
CONFIG_SKGE=y
CONFIG_SKGE_DEBUG=y
CONFIG_SKGE_GENESIS=y
CONFIG_SKY2=y
CONFIG_SKY2_DEBUG=y
CONFIG_OCTEON_EP=y
CONFIG_PRESTERA=y
CONFIG_PRESTERA_PCI=y
CONFIG_NET_VENDOR_MELLANOX=y
CONFIG_MLX4_EN=y
CONFIG_MLX4_EN_DCB=y
CONFIG_MLX4_CORE=y
CONFIG_MLX4_DEBUG=y
CONFIG_MLX4_CORE_GEN2=y
CONFIG_MLX5_CORE=y
CONFIG_MLX5_FPGA=y
CONFIG_MLX5_CORE_EN=y
CONFIG_MLX5_EN_ARFS=y
CONFIG_MLX5_EN_RXNFC=y
CONFIG_MLX5_MPFS=y
CONFIG_MLX5_ESWITCH=y
CONFIG_MLX5_BRIDGE=y
CONFIG_MLX5_CLS_ACT=y
CONFIG_MLX5_TC_CT=y
CONFIG_MLX5_TC_SAMPLE=y
CONFIG_MLX5_CORE_EN_DCB=y
CONFIG_MLX5_CORE_IPOIB=y
CONFIG_MLX5_EN_IPSEC=y
CONFIG_MLX5_EN_TLS=y
CONFIG_MLX5_SW_STEERING=y
CONFIG_MLX5_SF=y
CONFIG_MLX5_SF_MANAGER=y
CONFIG_MLXSW_CORE=y
CONFIG_MLXSW_CORE_HWMON=y
CONFIG_MLXSW_CORE_THERMAL=y
CONFIG_MLXSW_PCI=y
CONFIG_MLXSW_I2C=y
CONFIG_MLXSW_SPECTRUM=y
CONFIG_MLXSW_SPECTRUM_DCB=y
CONFIG_MLXSW_MINIMAL=y
CONFIG_MLXFW=y
CONFIG_NET_VENDOR_MICREL=y
CONFIG_KS8842=y
CONFIG_KS8851=y
CONFIG_KS8851_MLL=y
CONFIG_KSZ884X_PCI=y
CONFIG_NET_VENDOR_MICROCHIP=y
CONFIG_ENC28J60=y
CONFIG_ENC28J60_WRITEVERIFY=y
CONFIG_ENCX24J600=y
CONFIG_LAN743X=y
CONFIG_LAN966X_SWITCH=y
CONFIG_NET_VENDOR_MICROSEMI=y
CONFIG_MSCC_OCELOT_SWITCH_LIB=y
CONFIG_MSCC_OCELOT_SWITCH=y
CONFIG_NET_VENDOR_MICROSOFT=y
CONFIG_MICROSOFT_MANA=y
CONFIG_NET_VENDOR_MYRI=y
CONFIG_MYRI10GE=y
CONFIG_MYRI10GE_DCA=y
CONFIG_FEALNX=y
CONFIG_NET_VENDOR_NI=y
CONFIG_NI_XGE_MANAGEMENT_ENET=y
CONFIG_NET_VENDOR_NATSEMI=y
CONFIG_NATSEMI=y
CONFIG_NS83820=y
CONFIG_NET_VENDOR_NETERION=y
CONFIG_S2IO=y
CONFIG_NET_VENDOR_NETRONOME=y
CONFIG_NFP=y
CONFIG_NFP_APP_FLOWER=y
CONFIG_NFP_APP_ABM_NIC=y
CONFIG_NFP_DEBUG=y
CONFIG_NET_VENDOR_8390=y
CONFIG_PCMCIA_AXNET=y
CONFIG_NE2K_PCI=y
CONFIG_PCMCIA_PCNET=y
CONFIG_NET_VENDOR_NVIDIA=y
CONFIG_FORCEDETH=y
CONFIG_NET_VENDOR_OKI=y
CONFIG_ETHOC=y
CONFIG_NET_VENDOR_PACKET_ENGINES=y
CONFIG_HAMACHI=y
CONFIG_YELLOWFIN=y
CONFIG_NET_VENDOR_PENSANDO=y
CONFIG_IONIC=y
CONFIG_NET_VENDOR_QLOGIC=y
CONFIG_QLA3XXX=y
CONFIG_QLCNIC=y
CONFIG_QLCNIC_SRIOV=y
CONFIG_QLCNIC_DCB=y
CONFIG_QLCNIC_HWMON=y
CONFIG_NETXEN_NIC=y
CONFIG_QED=y
CONFIG_QED_LL2=y
CONFIG_QED_SRIOV=y
CONFIG_QEDE=y
CONFIG_QED_RDMA=y
CONFIG_QED_ISCSI=y
CONFIG_QED_FCOE=y
CONFIG_QED_OOO=y
CONFIG_NET_VENDOR_BROCADE=y
CONFIG_BNA=y
CONFIG_NET_VENDOR_QUALCOMM=y
CONFIG_QCA7000=y
CONFIG_QCA7000_SPI=y
CONFIG_QCA7000_UART=y
CONFIG_QCOM_EMAC=y
CONFIG_RMNET=y
CONFIG_NET_VENDOR_RDC=y
CONFIG_R6040=y
CONFIG_NET_VENDOR_REALTEK=y
CONFIG_ATP=y
CONFIG_8139CP=y
CONFIG_8139TOO=y
CONFIG_8139TOO_PIO=y
CONFIG_8139TOO_TUNE_TWISTER=y
CONFIG_8139TOO_8129=y
CONFIG_8139_OLD_RX_RESET=y
CONFIG_R8169=y
CONFIG_NET_VENDOR_RENESAS=y
CONFIG_NET_VENDOR_ROCKER=y
CONFIG_ROCKER=y
CONFIG_NET_VENDOR_SAMSUNG=y
CONFIG_SXGBE_ETH=y
CONFIG_NET_VENDOR_SEEQ=y
CONFIG_NET_VENDOR_SILAN=y
CONFIG_SC92031=y
CONFIG_NET_VENDOR_SIS=y
CONFIG_SIS900=y
CONFIG_SIS190=y
CONFIG_NET_VENDOR_SOLARFLARE=y
CONFIG_SFC=y
CONFIG_SFC_MTD=y
CONFIG_SFC_MCDI_MON=y
CONFIG_SFC_SRIOV=y
CONFIG_SFC_MCDI_LOGGING=y
CONFIG_SFC_FALCON=y
CONFIG_SFC_FALCON_MTD=y
CONFIG_SFC_SIENA=y
CONFIG_SFC_SIENA_MTD=y
CONFIG_SFC_SIENA_MCDI_MON=y
CONFIG_SFC_SIENA_SRIOV=y
CONFIG_SFC_SIENA_MCDI_LOGGING=y
CONFIG_NET_VENDOR_SMSC=y
CONFIG_PCMCIA_SMC91C92=y
CONFIG_EPIC100=y
CONFIG_SMSC911X=y
CONFIG_SMSC9420=y
CONFIG_NET_VENDOR_SOCIONEXT=y
CONFIG_NET_VENDOR_STMICRO=y
CONFIG_STMMAC_ETH=y
CONFIG_STMMAC_SELFTESTS=y
CONFIG_STMMAC_PLATFORM=y
CONFIG_DWMAC_DWC_QOS_ETH=y
CONFIG_DWMAC_GENERIC=y
CONFIG_DWMAC_INTEL_PLAT=y
CONFIG_DWMAC_INTEL=y
CONFIG_DWMAC_LOONGSON=y
CONFIG_STMMAC_PCI=y
CONFIG_NET_VENDOR_SUN=y
CONFIG_HAPPYMEAL=y
CONFIG_SUNGEM=y
CONFIG_CASSINI=y
CONFIG_NIU=y
CONFIG_NET_VENDOR_SYNOPSYS=y
CONFIG_DWC_XLGMAC=y
CONFIG_DWC_XLGMAC_PCI=y
CONFIG_NET_VENDOR_TEHUTI=y
CONFIG_TEHUTI=y
CONFIG_NET_VENDOR_TI=y
CONFIG_TI_CPSW_PHY_SEL=y
CONFIG_TLAN=y
CONFIG_NET_VENDOR_VERTEXCOM=y
CONFIG_MSE102X=y
CONFIG_NET_VENDOR_VIA=y
CONFIG_VIA_RHINE=y
CONFIG_VIA_RHINE_MMIO=y
CONFIG_VIA_VELOCITY=y
CONFIG_NET_VENDOR_WIZNET=y
CONFIG_WIZNET_W5100=y
CONFIG_WIZNET_W5300=y
# CONFIG_WIZNET_BUS_DIRECT is not set
# CONFIG_WIZNET_BUS_INDIRECT is not set
CONFIG_WIZNET_BUS_ANY=y
CONFIG_WIZNET_W5100_SPI=y
CONFIG_NET_VENDOR_XILINX=y
CONFIG_XILINX_EMACLITE=y
CONFIG_XILINX_AXI_EMAC=y
CONFIG_XILINX_LL_TEMAC=y
CONFIG_NET_VENDOR_XIRCOM=y
CONFIG_PCMCIA_XIRC2PS=y
CONFIG_FDDI=y
CONFIG_DEFXX=y
CONFIG_SKFP=y
CONFIG_HIPPI=y
CONFIG_ROADRUNNER=y
CONFIG_ROADRUNNER_LARGE_RINGS=y
CONFIG_NET_SB1000=y
CONFIG_PHYLINK=y
CONFIG_PHYLIB=y
CONFIG_SWPHY=y
CONFIG_LED_TRIGGER_PHY=y
CONFIG_FIXED_PHY=y
CONFIG_SFP=y

#
# MII PHY device drivers
#
CONFIG_AMD_PHY=y
CONFIG_ADIN_PHY=y
CONFIG_ADIN1100_PHY=y
CONFIG_AQUANTIA_PHY=y
CONFIG_AX88796B_PHY=y
CONFIG_BROADCOM_PHY=y
CONFIG_BCM54140_PHY=y
CONFIG_BCM7XXX_PHY=y
CONFIG_BCM84881_PHY=y
CONFIG_BCM87XX_PHY=y
CONFIG_BCM_NET_PHYLIB=y
CONFIG_BCM_NET_PHYPTP=y
CONFIG_CICADA_PHY=y
CONFIG_CORTINA_PHY=y
CONFIG_DAVICOM_PHY=y
CONFIG_ICPLUS_PHY=y
CONFIG_LXT_PHY=y
CONFIG_INTEL_XWAY_PHY=y
CONFIG_LSI_ET1011C_PHY=y
CONFIG_MARVELL_PHY=y
CONFIG_MARVELL_10G_PHY=y
CONFIG_MARVELL_88X2222_PHY=y
CONFIG_MAXLINEAR_GPHY=y
CONFIG_MEDIATEK_GE_PHY=y
CONFIG_MICREL_PHY=y
CONFIG_MICROCHIP_PHY=y
CONFIG_MICROCHIP_T1_PHY=y
CONFIG_MICROSEMI_PHY=y
CONFIG_MOTORCOMM_PHY=y
CONFIG_NATIONAL_PHY=y
CONFIG_NXP_C45_TJA11XX_PHY=y
CONFIG_NXP_TJA11XX_PHY=y
CONFIG_AT803X_PHY=y
CONFIG_QSEMI_PHY=y
CONFIG_REALTEK_PHY=y
CONFIG_RENESAS_PHY=y
CONFIG_ROCKCHIP_PHY=y
CONFIG_SMSC_PHY=y
CONFIG_STE10XP=y
CONFIG_TERANETICS_PHY=y
CONFIG_DP83822_PHY=y
CONFIG_DP83TC811_PHY=y
CONFIG_DP83848_PHY=y
CONFIG_DP83867_PHY=y
CONFIG_DP83869_PHY=y
CONFIG_DP83TD510_PHY=y
CONFIG_VITESSE_PHY=y
CONFIG_XILINX_GMII2RGMII=y
CONFIG_MICREL_KS8995MA=y
CONFIG_CAN_DEV=y
CONFIG_CAN_VCAN=y
CONFIG_CAN_VXCAN=y
CONFIG_CAN_NETLINK=y
CONFIG_CAN_CALC_BITTIMING=y
CONFIG_CAN_RX_OFFLOAD=y
CONFIG_CAN_CAN327=y
CONFIG_CAN_FLEXCAN=y
CONFIG_CAN_GRCAN=y
CONFIG_CAN_JANZ_ICAN3=y
CONFIG_CAN_KVASER_PCIEFD=y
CONFIG_CAN_SLCAN=y
CONFIG_CAN_C_CAN=y
CONFIG_CAN_C_CAN_PLATFORM=y
CONFIG_CAN_C_CAN_PCI=y
CONFIG_CAN_CC770=y
CONFIG_CAN_CC770_ISA=y
CONFIG_CAN_CC770_PLATFORM=y
CONFIG_CAN_CTUCANFD=y
CONFIG_CAN_CTUCANFD_PCI=y
CONFIG_CAN_CTUCANFD_PLATFORM=y
CONFIG_CAN_IFI_CANFD=y
CONFIG_CAN_M_CAN=y
CONFIG_CAN_M_CAN_PCI=y
CONFIG_CAN_M_CAN_PLATFORM=y
CONFIG_CAN_M_CAN_TCAN4X5X=y
CONFIG_CAN_PEAK_PCIEFD=y
CONFIG_CAN_SJA1000=y
CONFIG_CAN_EMS_PCI=y
CONFIG_CAN_EMS_PCMCIA=y
CONFIG_CAN_F81601=y
CONFIG_CAN_KVASER_PCI=y
CONFIG_CAN_PEAK_PCI=y
CONFIG_CAN_PEAK_PCIEC=y
CONFIG_CAN_PEAK_PCMCIA=y
CONFIG_CAN_PLX_PCI=y
CONFIG_CAN_SJA1000_ISA=y
CONFIG_CAN_SJA1000_PLATFORM=y
CONFIG_CAN_SOFTING=y
CONFIG_CAN_SOFTING_CS=y

#
# CAN SPI interfaces
#
CONFIG_CAN_HI311X=y
CONFIG_CAN_MCP251X=y
CONFIG_CAN_MCP251XFD=y
CONFIG_CAN_MCP251XFD_SANITY=y
# end of CAN SPI interfaces

#
# CAN USB interfaces
#
CONFIG_CAN_8DEV_USB=y
CONFIG_CAN_EMS_USB=y
CONFIG_CAN_ESD_USB=y
CONFIG_CAN_ETAS_ES58X=y
CONFIG_CAN_GS_USB=y
CONFIG_CAN_KVASER_USB=y
CONFIG_CAN_MCBA_USB=y
CONFIG_CAN_PEAK_USB=y
CONFIG_CAN_UCAN=y
# end of CAN USB interfaces

CONFIG_CAN_DEBUG_DEVICES=y

#
# MCTP Device Drivers
#
CONFIG_MCTP_SERIAL=y
CONFIG_MCTP_TRANSPORT_I2C=y
# end of MCTP Device Drivers

CONFIG_MDIO_DEVICE=y
CONFIG_MDIO_BUS=y
CONFIG_FWNODE_MDIO=y
CONFIG_OF_MDIO=y
CONFIG_ACPI_MDIO=y
CONFIG_MDIO_DEVRES=y
CONFIG_MDIO_BITBANG=y
CONFIG_MDIO_BCM_UNIMAC=y
CONFIG_MDIO_CAVIUM=y
CONFIG_MDIO_GPIO=y
CONFIG_MDIO_HISI_FEMAC=y
CONFIG_MDIO_I2C=y
CONFIG_MDIO_MVUSB=y
CONFIG_MDIO_MSCC_MIIM=y
CONFIG_MDIO_OCTEON=y
CONFIG_MDIO_IPQ4019=y
CONFIG_MDIO_IPQ8064=y
CONFIG_MDIO_THUNDER=y

#
# MDIO Multiplexers
#
CONFIG_MDIO_BUS_MUX=y
CONFIG_MDIO_BUS_MUX_GPIO=y
CONFIG_MDIO_BUS_MUX_MULTIPLEXER=y
CONFIG_MDIO_BUS_MUX_MMIOREG=y

#
# PCS device drivers
#
CONFIG_PCS_XPCS=y
CONFIG_PCS_LYNX=y
# end of PCS device drivers

CONFIG_PLIP=y
CONFIG_PPP=y
CONFIG_PPP_BSDCOMP=y
CONFIG_PPP_DEFLATE=y
CONFIG_PPP_FILTER=y
CONFIG_PPP_MPPE=y
CONFIG_PPP_MULTILINK=y
CONFIG_PPPOATM=y
CONFIG_PPPOE=y
CONFIG_PPTP=y
CONFIG_PPPOL2TP=y
CONFIG_PPP_ASYNC=y
CONFIG_PPP_SYNC_TTY=y
CONFIG_SLIP=y
CONFIG_SLHC=y
CONFIG_SLIP_COMPRESSED=y
CONFIG_SLIP_SMART=y
CONFIG_SLIP_MODE_SLIP6=y
CONFIG_USB_NET_DRIVERS=y
CONFIG_USB_CATC=y
CONFIG_USB_KAWETH=y
CONFIG_USB_PEGASUS=y
CONFIG_USB_RTL8150=y
CONFIG_USB_RTL8152=y
CONFIG_USB_LAN78XX=y
CONFIG_USB_USBNET=y
CONFIG_USB_NET_AX8817X=y
CONFIG_USB_NET_AX88179_178A=y
CONFIG_USB_NET_CDCETHER=y
CONFIG_USB_NET_CDC_EEM=y
CONFIG_USB_NET_CDC_NCM=y
CONFIG_USB_NET_HUAWEI_CDC_NCM=y
CONFIG_USB_NET_CDC_MBIM=y
CONFIG_USB_NET_DM9601=y
CONFIG_USB_NET_SR9700=y
CONFIG_USB_NET_SR9800=y
CONFIG_USB_NET_SMSC75XX=y
CONFIG_USB_NET_SMSC95XX=y
CONFIG_USB_NET_GL620A=y
CONFIG_USB_NET_NET1080=y
CONFIG_USB_NET_PLUSB=y
CONFIG_USB_NET_MCS7830=y
CONFIG_USB_NET_RNDIS_HOST=y
CONFIG_USB_NET_CDC_SUBSET_ENABLE=y
CONFIG_USB_NET_CDC_SUBSET=y
CONFIG_USB_ALI_M5632=y
CONFIG_USB_AN2720=y
CONFIG_USB_BELKIN=y
CONFIG_USB_ARMLINUX=y
CONFIG_USB_EPSON2888=y
CONFIG_USB_KC2190=y
CONFIG_USB_NET_ZAURUS=y
CONFIG_USB_NET_CX82310_ETH=y
CONFIG_USB_NET_KALMIA=y
CONFIG_USB_NET_QMI_WWAN=y
CONFIG_USB_HSO=y
CONFIG_USB_NET_INT51X1=y
CONFIG_USB_CDC_PHONET=y
CONFIG_USB_IPHETH=y
CONFIG_USB_SIERRA_NET=y
CONFIG_USB_VL600=y
CONFIG_USB_NET_CH9200=y
CONFIG_USB_NET_AQC111=y
CONFIG_USB_RTL8153_ECM=y
CONFIG_WLAN=y
CONFIG_WLAN_VENDOR_ADMTEK=y
CONFIG_ADM8211=y
CONFIG_ATH_COMMON=y
CONFIG_WLAN_VENDOR_ATH=y
CONFIG_ATH_DEBUG=y
CONFIG_ATH_TRACEPOINTS=y
CONFIG_ATH_REG_DYNAMIC_USER_REG_HINTS=y
CONFIG_ATH_REG_DYNAMIC_USER_CERT_TESTING=y
CONFIG_ATH5K=y
CONFIG_ATH5K_DEBUG=y
CONFIG_ATH5K_TRACER=y
CONFIG_ATH5K_PCI=y
CONFIG_ATH5K_TEST_CHANNELS=y
CONFIG_ATH9K_HW=y
CONFIG_ATH9K_COMMON=y
CONFIG_ATH9K_COMMON_DEBUG=y
CONFIG_ATH9K_DFS_DEBUGFS=y
CONFIG_ATH9K_BTCOEX_SUPPORT=y
CONFIG_ATH9K=y
CONFIG_ATH9K_PCI=y
CONFIG_ATH9K_AHB=y
CONFIG_ATH9K_DEBUGFS=y
CONFIG_ATH9K_STATION_STATISTICS=y
CONFIG_ATH9K_TX99=y
CONFIG_ATH9K_DFS_CERTIFIED=y
CONFIG_ATH9K_DYNACK=y
CONFIG_ATH9K_WOW=y
CONFIG_ATH9K_RFKILL=y
CONFIG_ATH9K_CHANNEL_CONTEXT=y
CONFIG_ATH9K_PCOEM=y
CONFIG_ATH9K_PCI_NO_EEPROM=y
CONFIG_ATH9K_HTC=y
CONFIG_ATH9K_HTC_DEBUGFS=y
CONFIG_ATH9K_HWRNG=y
CONFIG_ATH9K_COMMON_SPECTRAL=y
CONFIG_CARL9170=y
CONFIG_CARL9170_LEDS=y
CONFIG_CARL9170_DEBUGFS=y
CONFIG_CARL9170_WPC=y
CONFIG_CARL9170_HWRNG=y
CONFIG_ATH6KL=y
CONFIG_ATH6KL_SDIO=y
CONFIG_ATH6KL_USB=y
CONFIG_ATH6KL_DEBUG=y
CONFIG_ATH6KL_TRACING=y
CONFIG_ATH6KL_REGDOMAIN=y
CONFIG_AR5523=y
CONFIG_WIL6210=y
CONFIG_WIL6210_ISR_COR=y
CONFIG_WIL6210_TRACING=y
CONFIG_WIL6210_DEBUGFS=y
CONFIG_ATH10K=y
CONFIG_ATH10K_CE=y
CONFIG_ATH10K_PCI=y
CONFIG_ATH10K_AHB=y
CONFIG_ATH10K_SDIO=y
CONFIG_ATH10K_USB=y
CONFIG_ATH10K_DEBUG=y
CONFIG_ATH10K_DEBUGFS=y
CONFIG_ATH10K_SPECTRAL=y
CONFIG_ATH10K_TRACING=y
CONFIG_ATH10K_DFS_CERTIFIED=y
CONFIG_WCN36XX=y
CONFIG_WCN36XX_DEBUGFS=y
CONFIG_ATH11K=y
CONFIG_ATH11K_AHB=y
CONFIG_ATH11K_PCI=y
CONFIG_ATH11K_DEBUG=y
CONFIG_ATH11K_DEBUGFS=y
CONFIG_ATH11K_TRACING=y
CONFIG_ATH11K_SPECTRAL=y
CONFIG_WLAN_VENDOR_ATMEL=y
CONFIG_ATMEL=y
CONFIG_PCI_ATMEL=y
CONFIG_PCMCIA_ATMEL=y
CONFIG_AT76C50X_USB=y
CONFIG_WLAN_VENDOR_BROADCOM=y
CONFIG_B43=y
CONFIG_B43_BCMA=y
CONFIG_B43_SSB=y
CONFIG_B43_BUSES_BCMA_AND_SSB=y
# CONFIG_B43_BUSES_BCMA is not set
# CONFIG_B43_BUSES_SSB is not set
CONFIG_B43_PCI_AUTOSELECT=y
CONFIG_B43_PCICORE_AUTOSELECT=y
CONFIG_B43_SDIO=y
CONFIG_B43_BCMA_PIO=y
CONFIG_B43_PIO=y
CONFIG_B43_PHY_G=y
CONFIG_B43_PHY_N=y
CONFIG_B43_PHY_LP=y
CONFIG_B43_PHY_HT=y
CONFIG_B43_LEDS=y
CONFIG_B43_HWRNG=y
CONFIG_B43_DEBUG=y
CONFIG_B43LEGACY=y
CONFIG_B43LEGACY_PCI_AUTOSELECT=y
CONFIG_B43LEGACY_PCICORE_AUTOSELECT=y
CONFIG_B43LEGACY_LEDS=y
CONFIG_B43LEGACY_HWRNG=y
CONFIG_B43LEGACY_DEBUG=y
CONFIG_B43LEGACY_DMA=y
CONFIG_B43LEGACY_PIO=y
CONFIG_B43LEGACY_DMA_AND_PIO_MODE=y
# CONFIG_B43LEGACY_DMA_MODE is not set
# CONFIG_B43LEGACY_PIO_MODE is not set
CONFIG_BRCMUTIL=y
CONFIG_BRCMSMAC=y
CONFIG_BRCMSMAC_LEDS=y
CONFIG_BRCMFMAC=y
CONFIG_BRCMFMAC_PROTO_BCDC=y
CONFIG_BRCMFMAC_PROTO_MSGBUF=y
CONFIG_BRCMFMAC_SDIO=y
CONFIG_BRCMFMAC_USB=y
CONFIG_BRCMFMAC_PCIE=y
CONFIG_BRCM_TRACING=y
CONFIG_BRCMDBG=y
CONFIG_WLAN_VENDOR_CISCO=y
CONFIG_AIRO=y
CONFIG_AIRO_CS=y
CONFIG_WLAN_VENDOR_INTEL=y
CONFIG_IPW2100=y
CONFIG_IPW2100_MONITOR=y
CONFIG_IPW2100_DEBUG=y
CONFIG_IPW2200=y
CONFIG_IPW2200_MONITOR=y
CONFIG_IPW2200_RADIOTAP=y
CONFIG_IPW2200_PROMISCUOUS=y
CONFIG_IPW2200_QOS=y
CONFIG_IPW2200_DEBUG=y
CONFIG_LIBIPW=y
CONFIG_LIBIPW_DEBUG=y
CONFIG_IWLEGACY=y
CONFIG_IWL4965=y
CONFIG_IWL3945=y

#
# iwl3945 / iwl4965 Debugging Options
#
CONFIG_IWLEGACY_DEBUG=y
CONFIG_IWLEGACY_DEBUGFS=y
# end of iwl3945 / iwl4965 Debugging Options

CONFIG_IWLWIFI=y
CONFIG_IWLWIFI_LEDS=y
CONFIG_IWLDVM=y
CONFIG_IWLMVM=y

#
# Debugging Options
#
CONFIG_IWLWIFI_DEBUG=y
CONFIG_IWLWIFI_DEBUGFS=y
CONFIG_IWLWIFI_DEVICE_TRACING=y
# end of Debugging Options

CONFIG_IWLMEI=y
CONFIG_WLAN_VENDOR_INTERSIL=y
CONFIG_HOSTAP=y
CONFIG_HOSTAP_FIRMWARE=y
CONFIG_HOSTAP_FIRMWARE_NVRAM=y
CONFIG_HOSTAP_PLX=y
CONFIG_HOSTAP_PCI=y
CONFIG_HOSTAP_CS=y
CONFIG_HERMES=y
CONFIG_HERMES_PRISM=y
CONFIG_HERMES_CACHE_FW_ON_INIT=y
CONFIG_PLX_HERMES=y
CONFIG_TMD_HERMES=y
CONFIG_NORTEL_HERMES=y
CONFIG_PCI_HERMES=y
CONFIG_PCMCIA_HERMES=y
CONFIG_PCMCIA_SPECTRUM=y
CONFIG_ORINOCO_USB=y
CONFIG_P54_COMMON=y
CONFIG_P54_USB=y
CONFIG_P54_PCI=y
CONFIG_P54_SPI=y
CONFIG_P54_SPI_DEFAULT_EEPROM=y
CONFIG_P54_LEDS=y
CONFIG_WLAN_VENDOR_MARVELL=y
CONFIG_LIBERTAS=y
CONFIG_LIBERTAS_USB=y
CONFIG_LIBERTAS_CS=y
CONFIG_LIBERTAS_SDIO=y
CONFIG_LIBERTAS_SPI=y
CONFIG_LIBERTAS_DEBUG=y
CONFIG_LIBERTAS_MESH=y
CONFIG_LIBERTAS_THINFIRM=y
CONFIG_LIBERTAS_THINFIRM_DEBUG=y
CONFIG_LIBERTAS_THINFIRM_USB=y
CONFIG_MWIFIEX=y
CONFIG_MWIFIEX_SDIO=y
CONFIG_MWIFIEX_PCIE=y
CONFIG_MWIFIEX_USB=y
CONFIG_MWL8K=y
CONFIG_WLAN_VENDOR_MEDIATEK=y
CONFIG_MT7601U=y
CONFIG_MT76_CORE=y
CONFIG_MT76_LEDS=y
CONFIG_MT76_USB=y
CONFIG_MT76_SDIO=y
CONFIG_MT76x02_LIB=y
CONFIG_MT76x02_USB=y
CONFIG_MT76_CONNAC_LIB=y
CONFIG_MT76x0_COMMON=y
CONFIG_MT76x0U=y
CONFIG_MT76x0E=y
CONFIG_MT76x2_COMMON=y
CONFIG_MT76x2E=y
CONFIG_MT76x2U=y
CONFIG_MT7603E=y
CONFIG_MT7615_COMMON=y
CONFIG_MT7615E=y
CONFIG_MT7663_USB_SDIO_COMMON=y
CONFIG_MT7663U=y
CONFIG_MT7663S=y
CONFIG_MT7915E=y
CONFIG_MT7921_COMMON=y
CONFIG_MT7921E=y
CONFIG_MT7921S=y
CONFIG_MT7921U=y
CONFIG_WLAN_VENDOR_MICROCHIP=y
CONFIG_WILC1000=y
CONFIG_WILC1000_SDIO=y
CONFIG_WILC1000_SPI=y
CONFIG_WILC1000_HW_OOB_INTR=y
CONFIG_WLAN_VENDOR_PURELIFI=y
CONFIG_PLFXLC=y
CONFIG_WLAN_VENDOR_RALINK=y
CONFIG_RT2X00=y
CONFIG_RT2400PCI=y
CONFIG_RT2500PCI=y
CONFIG_RT61PCI=y
CONFIG_RT2800PCI=y
CONFIG_RT2800PCI_RT33XX=y
CONFIG_RT2800PCI_RT35XX=y
CONFIG_RT2800PCI_RT53XX=y
CONFIG_RT2800PCI_RT3290=y
CONFIG_RT2500USB=y
CONFIG_RT73USB=y
CONFIG_RT2800USB=y
CONFIG_RT2800USB_RT33XX=y
CONFIG_RT2800USB_RT35XX=y
CONFIG_RT2800USB_RT3573=y
CONFIG_RT2800USB_RT53XX=y
CONFIG_RT2800USB_RT55XX=y
CONFIG_RT2800USB_UNKNOWN=y
CONFIG_RT2800_LIB=y
CONFIG_RT2800_LIB_MMIO=y
CONFIG_RT2X00_LIB_MMIO=y
CONFIG_RT2X00_LIB_PCI=y
CONFIG_RT2X00_LIB_USB=y
CONFIG_RT2X00_LIB=y
CONFIG_RT2X00_LIB_FIRMWARE=y
CONFIG_RT2X00_LIB_CRYPTO=y
CONFIG_RT2X00_LIB_LEDS=y
CONFIG_RT2X00_LIB_DEBUGFS=y
CONFIG_RT2X00_DEBUG=y
CONFIG_WLAN_VENDOR_REALTEK=y
CONFIG_RTL8180=y
CONFIG_RTL8187=y
CONFIG_RTL8187_LEDS=y
CONFIG_RTL_CARDS=y
CONFIG_RTL8192CE=y
CONFIG_RTL8192SE=y
CONFIG_RTL8192DE=y
CONFIG_RTL8723AE=y
CONFIG_RTL8723BE=y
CONFIG_RTL8188EE=y
CONFIG_RTL8192EE=y
CONFIG_RTL8821AE=y
CONFIG_RTL8192CU=y
CONFIG_RTLWIFI=y
CONFIG_RTLWIFI_PCI=y
CONFIG_RTLWIFI_USB=y
CONFIG_RTLWIFI_DEBUG=y
CONFIG_RTL8192C_COMMON=y
CONFIG_RTL8723_COMMON=y
CONFIG_RTLBTCOEXIST=y
CONFIG_RTL8XXXU=y
CONFIG_RTL8XXXU_UNTESTED=y
CONFIG_RTW88=y
CONFIG_RTW88_CORE=y
CONFIG_RTW88_PCI=y
CONFIG_RTW88_8822B=y
CONFIG_RTW88_8822C=y
CONFIG_RTW88_8723D=y
CONFIG_RTW88_8821C=y
CONFIG_RTW88_8822BE=y
CONFIG_RTW88_8822CE=y
CONFIG_RTW88_8723DE=y
CONFIG_RTW88_8821CE=y
CONFIG_RTW88_DEBUG=y
CONFIG_RTW88_DEBUGFS=y
CONFIG_RTW89=y
CONFIG_RTW89_CORE=y
CONFIG_RTW89_PCI=y
CONFIG_RTW89_8852A=y
CONFIG_RTW89_8852C=y
CONFIG_RTW89_8852AE=y
CONFIG_RTW89_8852CE=y
CONFIG_RTW89_DEBUG=y
CONFIG_RTW89_DEBUGMSG=y
CONFIG_RTW89_DEBUGFS=y
CONFIG_WLAN_VENDOR_RSI=y
CONFIG_RSI_91X=y
CONFIG_RSI_DEBUGFS=y
CONFIG_RSI_SDIO=y
CONFIG_RSI_USB=y
CONFIG_RSI_COEX=y
CONFIG_WLAN_VENDOR_SILABS=y
CONFIG_WFX=y
CONFIG_WLAN_VENDOR_ST=y
CONFIG_CW1200=y
CONFIG_CW1200_WLAN_SDIO=y
CONFIG_CW1200_WLAN_SPI=y
CONFIG_WLAN_VENDOR_TI=y
CONFIG_WL1251=y
CONFIG_WL1251_SPI=y
CONFIG_WL1251_SDIO=y
CONFIG_WL12XX=y
CONFIG_WL18XX=y
CONFIG_WLCORE=y
CONFIG_WLCORE_SPI=y
CONFIG_WLCORE_SDIO=y
CONFIG_WILINK_PLATFORM_DATA=y
CONFIG_WLAN_VENDOR_ZYDAS=y
CONFIG_USB_ZD1201=y
CONFIG_ZD1211RW=y
CONFIG_ZD1211RW_DEBUG=y
CONFIG_WLAN_VENDOR_QUANTENNA=y
CONFIG_QTNFMAC=y
CONFIG_QTNFMAC_PCIE=y
CONFIG_PCMCIA_RAYCS=y
CONFIG_PCMCIA_WL3501=y
CONFIG_MAC80211_HWSIM=y
CONFIG_USB_NET_RNDIS_WLAN=y
CONFIG_VIRT_WIFI=y
CONFIG_WAN=y
CONFIG_HDLC=y
CONFIG_HDLC_RAW=y
CONFIG_HDLC_RAW_ETH=y
CONFIG_HDLC_CISCO=y
CONFIG_HDLC_FR=y
CONFIG_HDLC_PPP=y
CONFIG_HDLC_X25=y
CONFIG_PCI200SYN=y
CONFIG_WANXL=y
CONFIG_PC300TOO=y
CONFIG_FARSYNC=y
CONFIG_LAPBETHER=y
CONFIG_IEEE802154_DRIVERS=y
CONFIG_IEEE802154_FAKELB=y
CONFIG_IEEE802154_AT86RF230=y
CONFIG_IEEE802154_MRF24J40=y
CONFIG_IEEE802154_CC2520=y
CONFIG_IEEE802154_ATUSB=y
CONFIG_IEEE802154_ADF7242=y
CONFIG_IEEE802154_CA8210=y
CONFIG_IEEE802154_CA8210_DEBUGFS=y
CONFIG_IEEE802154_MCR20A=y
CONFIG_IEEE802154_HWSIM=y

#
# Wireless WAN
#
CONFIG_WWAN=y
CONFIG_WWAN_DEBUGFS=y
CONFIG_WWAN_HWSIM=y
CONFIG_MHI_WWAN_CTRL=y
CONFIG_MHI_WWAN_MBIM=y
CONFIG_RPMSG_WWAN_CTRL=y
CONFIG_IOSM=y
CONFIG_MTK_T7XX=y
# end of Wireless WAN

CONFIG_XEN_NETDEV_FRONTEND=y
CONFIG_XEN_NETDEV_BACKEND=y
CONFIG_VMXNET3=y
CONFIG_FUJITSU_ES=y
CONFIG_USB4_NET=y
CONFIG_HYPERV_NET=y
CONFIG_NETDEVSIM=y
CONFIG_NET_FAILOVER=y
CONFIG_ISDN=y
CONFIG_ISDN_CAPI=y
CONFIG_CAPI_TRACE=y
CONFIG_ISDN_CAPI_MIDDLEWARE=y
CONFIG_MISDN=y
CONFIG_MISDN_DSP=y
CONFIG_MISDN_L1OIP=y

#
# mISDN hardware drivers
#
CONFIG_MISDN_HFCPCI=y
CONFIG_MISDN_HFCMULTI=y
CONFIG_MISDN_HFCUSB=y
CONFIG_MISDN_AVMFRITZ=y
CONFIG_MISDN_SPEEDFAX=y
CONFIG_MISDN_INFINEON=y
CONFIG_MISDN_W6692=y
CONFIG_MISDN_NETJET=y
CONFIG_MISDN_HDLC=y
CONFIG_MISDN_IPAC=y
CONFIG_MISDN_ISAR=y

#
# Input device support
#
CONFIG_INPUT=y
CONFIG_INPUT_LEDS=y
CONFIG_INPUT_FF_MEMLESS=y
CONFIG_INPUT_SPARSEKMAP=y
CONFIG_INPUT_MATRIXKMAP=y
CONFIG_INPUT_VIVALDIFMAP=y

#
# Userland interfaces
#
CONFIG_INPUT_MOUSEDEV=y
CONFIG_INPUT_MOUSEDEV_PSAUX=y
CONFIG_INPUT_MOUSEDEV_SCREEN_X=1024
CONFIG_INPUT_MOUSEDEV_SCREEN_Y=768
CONFIG_INPUT_JOYDEV=y
CONFIG_INPUT_EVDEV=y
CONFIG_INPUT_EVBUG=y

#
# Input Device Drivers
#
CONFIG_INPUT_KEYBOARD=y
CONFIG_KEYBOARD_ADC=y
CONFIG_KEYBOARD_ADP5520=y
CONFIG_KEYBOARD_ADP5588=y
CONFIG_KEYBOARD_ADP5589=y
CONFIG_KEYBOARD_APPLESPI=y
CONFIG_KEYBOARD_ATKBD=y
CONFIG_KEYBOARD_QT1050=y
CONFIG_KEYBOARD_QT1070=y
CONFIG_KEYBOARD_QT2160=y
CONFIG_KEYBOARD_DLINK_DIR685=y
CONFIG_KEYBOARD_LKKBD=y
CONFIG_KEYBOARD_GPIO=y
CONFIG_KEYBOARD_GPIO_POLLED=y
CONFIG_KEYBOARD_TCA6416=y
CONFIG_KEYBOARD_TCA8418=y
CONFIG_KEYBOARD_MATRIX=y
CONFIG_KEYBOARD_LM8323=y
CONFIG_KEYBOARD_LM8333=y
CONFIG_KEYBOARD_MAX7359=y
CONFIG_KEYBOARD_MCS=y
CONFIG_KEYBOARD_MPR121=y
CONFIG_KEYBOARD_NEWTON=y
CONFIG_KEYBOARD_OPENCORES=y
CONFIG_KEYBOARD_SAMSUNG=y
CONFIG_KEYBOARD_GOLDFISH_EVENTS=y
CONFIG_KEYBOARD_STOWAWAY=y
CONFIG_KEYBOARD_SUNKBD=y
CONFIG_KEYBOARD_STMPE=y
CONFIG_KEYBOARD_IQS62X=y
CONFIG_KEYBOARD_OMAP4=y
CONFIG_KEYBOARD_TC3589X=y
CONFIG_KEYBOARD_TM2_TOUCHKEY=y
CONFIG_KEYBOARD_TWL4030=y
CONFIG_KEYBOARD_XTKBD=y
CONFIG_KEYBOARD_CROS_EC=y
CONFIG_KEYBOARD_CAP11XX=y
CONFIG_KEYBOARD_BCM=y
CONFIG_KEYBOARD_MTK_PMIC=y
CONFIG_KEYBOARD_CYPRESS_SF=y
CONFIG_INPUT_MOUSE=y
CONFIG_MOUSE_PS2=y
CONFIG_MOUSE_PS2_ALPS=y
CONFIG_MOUSE_PS2_BYD=y
CONFIG_MOUSE_PS2_LOGIPS2PP=y
CONFIG_MOUSE_PS2_SYNAPTICS=y
CONFIG_MOUSE_PS2_SYNAPTICS_SMBUS=y
CONFIG_MOUSE_PS2_CYPRESS=y
CONFIG_MOUSE_PS2_LIFEBOOK=y
CONFIG_MOUSE_PS2_TRACKPOINT=y
CONFIG_MOUSE_PS2_ELANTECH=y
CONFIG_MOUSE_PS2_ELANTECH_SMBUS=y
CONFIG_MOUSE_PS2_SENTELIC=y
CONFIG_MOUSE_PS2_TOUCHKIT=y
CONFIG_MOUSE_PS2_FOCALTECH=y
CONFIG_MOUSE_PS2_VMMOUSE=y
CONFIG_MOUSE_PS2_SMBUS=y
CONFIG_MOUSE_SERIAL=y
CONFIG_MOUSE_APPLETOUCH=y
CONFIG_MOUSE_BCM5974=y
CONFIG_MOUSE_CYAPA=y
CONFIG_MOUSE_ELAN_I2C=y
CONFIG_MOUSE_ELAN_I2C_I2C=y
CONFIG_MOUSE_ELAN_I2C_SMBUS=y
CONFIG_MOUSE_VSXXXAA=y
CONFIG_MOUSE_GPIO=y
CONFIG_MOUSE_SYNAPTICS_I2C=y
CONFIG_MOUSE_SYNAPTICS_USB=y
CONFIG_INPUT_JOYSTICK=y
CONFIG_JOYSTICK_ANALOG=y
CONFIG_JOYSTICK_A3D=y
CONFIG_JOYSTICK_ADC=y
CONFIG_JOYSTICK_ADI=y
CONFIG_JOYSTICK_COBRA=y
CONFIG_JOYSTICK_GF2K=y
CONFIG_JOYSTICK_GRIP=y
CONFIG_JOYSTICK_GRIP_MP=y
CONFIG_JOYSTICK_GUILLEMOT=y
CONFIG_JOYSTICK_INTERACT=y
CONFIG_JOYSTICK_SIDEWINDER=y
CONFIG_JOYSTICK_TMDC=y
CONFIG_JOYSTICK_IFORCE=y
CONFIG_JOYSTICK_IFORCE_USB=y
CONFIG_JOYSTICK_IFORCE_232=y
CONFIG_JOYSTICK_WARRIOR=y
CONFIG_JOYSTICK_MAGELLAN=y
CONFIG_JOYSTICK_SPACEORB=y
CONFIG_JOYSTICK_SPACEBALL=y
CONFIG_JOYSTICK_STINGER=y
CONFIG_JOYSTICK_TWIDJOY=y
CONFIG_JOYSTICK_ZHENHUA=y
CONFIG_JOYSTICK_DB9=y
CONFIG_JOYSTICK_GAMECON=y
CONFIG_JOYSTICK_TURBOGRAFX=y
CONFIG_JOYSTICK_AS5011=y
CONFIG_JOYSTICK_JOYDUMP=y
CONFIG_JOYSTICK_XPAD=y
CONFIG_JOYSTICK_XPAD_FF=y
CONFIG_JOYSTICK_XPAD_LEDS=y
CONFIG_JOYSTICK_WALKERA0701=y
CONFIG_JOYSTICK_PSXPAD_SPI=y
CONFIG_JOYSTICK_PSXPAD_SPI_FF=y
CONFIG_JOYSTICK_PXRC=y
CONFIG_JOYSTICK_QWIIC=y
CONFIG_JOYSTICK_FSIA6B=y
CONFIG_JOYSTICK_SENSEHAT=y
CONFIG_INPUT_TABLET=y
CONFIG_TABLET_USB_ACECAD=y
CONFIG_TABLET_USB_AIPTEK=y
CONFIG_TABLET_USB_HANWANG=y
CONFIG_TABLET_USB_KBTAB=y
CONFIG_TABLET_USB_PEGASUS=y
CONFIG_TABLET_SERIAL_WACOM4=y
CONFIG_INPUT_TOUCHSCREEN=y
CONFIG_TOUCHSCREEN_88PM860X=y
CONFIG_TOUCHSCREEN_ADS7846=y
CONFIG_TOUCHSCREEN_AD7877=y
CONFIG_TOUCHSCREEN_AD7879=y
CONFIG_TOUCHSCREEN_AD7879_I2C=y
CONFIG_TOUCHSCREEN_AD7879_SPI=y
CONFIG_TOUCHSCREEN_ADC=y
CONFIG_TOUCHSCREEN_AR1021_I2C=y
CONFIG_TOUCHSCREEN_ATMEL_MXT=y
CONFIG_TOUCHSCREEN_ATMEL_MXT_T37=y
CONFIG_TOUCHSCREEN_AUO_PIXCIR=y
CONFIG_TOUCHSCREEN_BU21013=y
CONFIG_TOUCHSCREEN_BU21029=y
CONFIG_TOUCHSCREEN_CHIPONE_ICN8318=y
CONFIG_TOUCHSCREEN_CHIPONE_ICN8505=y
CONFIG_TOUCHSCREEN_CY8CTMA140=y
CONFIG_TOUCHSCREEN_CY8CTMG110=y
CONFIG_TOUCHSCREEN_CYTTSP_CORE=y
CONFIG_TOUCHSCREEN_CYTTSP_I2C=y
CONFIG_TOUCHSCREEN_CYTTSP_SPI=y
CONFIG_TOUCHSCREEN_CYTTSP4_CORE=y
CONFIG_TOUCHSCREEN_CYTTSP4_I2C=y
CONFIG_TOUCHSCREEN_CYTTSP4_SPI=y
CONFIG_TOUCHSCREEN_DA9034=y
CONFIG_TOUCHSCREEN_DA9052=y
CONFIG_TOUCHSCREEN_DYNAPRO=y
CONFIG_TOUCHSCREEN_HAMPSHIRE=y
CONFIG_TOUCHSCREEN_EETI=y
CONFIG_TOUCHSCREEN_EGALAX=y
CONFIG_TOUCHSCREEN_EGALAX_SERIAL=y
CONFIG_TOUCHSCREEN_EXC3000=y
CONFIG_TOUCHSCREEN_FUJITSU=y
CONFIG_TOUCHSCREEN_GOODIX=y
CONFIG_TOUCHSCREEN_HIDEEP=y
CONFIG_TOUCHSCREEN_HYCON_HY46XX=y
CONFIG_TOUCHSCREEN_ILI210X=y
CONFIG_TOUCHSCREEN_ILITEK=y
CONFIG_TOUCHSCREEN_S6SY761=y
CONFIG_TOUCHSCREEN_GUNZE=y
CONFIG_TOUCHSCREEN_EKTF2127=y
CONFIG_TOUCHSCREEN_ELAN=y
CONFIG_TOUCHSCREEN_ELO=y
CONFIG_TOUCHSCREEN_WACOM_W8001=y
CONFIG_TOUCHSCREEN_WACOM_I2C=y
CONFIG_TOUCHSCREEN_MAX11801=y
CONFIG_TOUCHSCREEN_MCS5000=y
CONFIG_TOUCHSCREEN_MMS114=y
CONFIG_TOUCHSCREEN_MELFAS_MIP4=y
CONFIG_TOUCHSCREEN_MSG2638=y
CONFIG_TOUCHSCREEN_MTOUCH=y
CONFIG_TOUCHSCREEN_IMAGIS=y
CONFIG_TOUCHSCREEN_IMX6UL_TSC=y
CONFIG_TOUCHSCREEN_INEXIO=y
CONFIG_TOUCHSCREEN_MK712=y
CONFIG_TOUCHSCREEN_PENMOUNT=y
CONFIG_TOUCHSCREEN_EDT_FT5X06=y
CONFIG_TOUCHSCREEN_TOUCHRIGHT=y
CONFIG_TOUCHSCREEN_TOUCHWIN=y
CONFIG_TOUCHSCREEN_TI_AM335X_TSC=y
CONFIG_TOUCHSCREEN_UCB1400=y
CONFIG_TOUCHSCREEN_PIXCIR=y
CONFIG_TOUCHSCREEN_WDT87XX_I2C=y
CONFIG_TOUCHSCREEN_WM831X=y
CONFIG_TOUCHSCREEN_WM97XX=y
CONFIG_TOUCHSCREEN_WM9705=y
CONFIG_TOUCHSCREEN_WM9712=y
CONFIG_TOUCHSCREEN_WM9713=y
CONFIG_TOUCHSCREEN_USB_COMPOSITE=y
CONFIG_TOUCHSCREEN_MC13783=y
CONFIG_TOUCHSCREEN_USB_EGALAX=y
CONFIG_TOUCHSCREEN_USB_PANJIT=y
CONFIG_TOUCHSCREEN_USB_3M=y
CONFIG_TOUCHSCREEN_USB_ITM=y
CONFIG_TOUCHSCREEN_USB_ETURBO=y
CONFIG_TOUCHSCREEN_USB_GUNZE=y
CONFIG_TOUCHSCREEN_USB_DMC_TSC10=y
CONFIG_TOUCHSCREEN_USB_IRTOUCH=y
CONFIG_TOUCHSCREEN_USB_IDEALTEK=y
CONFIG_TOUCHSCREEN_USB_GENERAL_TOUCH=y
CONFIG_TOUCHSCREEN_USB_GOTOP=y
CONFIG_TOUCHSCREEN_USB_JASTEC=y
CONFIG_TOUCHSCREEN_USB_ELO=y
CONFIG_TOUCHSCREEN_USB_E2I=y
CONFIG_TOUCHSCREEN_USB_ZYTRONIC=y
CONFIG_TOUCHSCREEN_USB_ETT_TC45USB=y
CONFIG_TOUCHSCREEN_USB_NEXIO=y
CONFIG_TOUCHSCREEN_USB_EASYTOUCH=y
CONFIG_TOUCHSCREEN_TOUCHIT213=y
CONFIG_TOUCHSCREEN_TSC_SERIO=y
CONFIG_TOUCHSCREEN_TSC200X_CORE=y
CONFIG_TOUCHSCREEN_TSC2004=y
CONFIG_TOUCHSCREEN_TSC2005=y
CONFIG_TOUCHSCREEN_TSC2007=y
CONFIG_TOUCHSCREEN_TSC2007_IIO=y
CONFIG_TOUCHSCREEN_PCAP=y
CONFIG_TOUCHSCREEN_RM_TS=y
CONFIG_TOUCHSCREEN_SILEAD=y
CONFIG_TOUCHSCREEN_SIS_I2C=y
CONFIG_TOUCHSCREEN_ST1232=y
CONFIG_TOUCHSCREEN_STMFTS=y
CONFIG_TOUCHSCREEN_STMPE=y
CONFIG_TOUCHSCREEN_SUR40=y
CONFIG_TOUCHSCREEN_SURFACE3_SPI=y
CONFIG_TOUCHSCREEN_SX8654=y
CONFIG_TOUCHSCREEN_TPS6507X=y
CONFIG_TOUCHSCREEN_ZET6223=y
CONFIG_TOUCHSCREEN_ZFORCE=y
CONFIG_TOUCHSCREEN_COLIBRI_VF50=y
CONFIG_TOUCHSCREEN_ROHM_BU21023=y
CONFIG_TOUCHSCREEN_IQS5XX=y
CONFIG_TOUCHSCREEN_ZINITIX=y
CONFIG_INPUT_MISC=y
CONFIG_INPUT_88PM860X_ONKEY=y
CONFIG_INPUT_88PM80X_ONKEY=y
CONFIG_INPUT_AD714X=y
CONFIG_INPUT_AD714X_I2C=y
CONFIG_INPUT_AD714X_SPI=y
CONFIG_INPUT_ARIZONA_HAPTICS=y
CONFIG_INPUT_ATC260X_ONKEY=y
CONFIG_INPUT_ATMEL_CAPTOUCH=y
CONFIG_INPUT_BMA150=y
CONFIG_INPUT_E3X0_BUTTON=y
CONFIG_INPUT_PCSPKR=y
CONFIG_INPUT_MAX77650_ONKEY=y
CONFIG_INPUT_MAX77693_HAPTIC=y
CONFIG_INPUT_MAX8925_ONKEY=y
CONFIG_INPUT_MAX8997_HAPTIC=y
CONFIG_INPUT_MC13783_PWRBUTTON=y
CONFIG_INPUT_MMA8450=y
CONFIG_INPUT_APANEL=y
CONFIG_INPUT_GPIO_BEEPER=y
CONFIG_INPUT_GPIO_DECODER=y
CONFIG_INPUT_GPIO_VIBRA=y
CONFIG_INPUT_CPCAP_PWRBUTTON=y
CONFIG_INPUT_ATLAS_BTNS=y
CONFIG_INPUT_ATI_REMOTE2=y
CONFIG_INPUT_KEYSPAN_REMOTE=y
CONFIG_INPUT_KXTJ9=y
CONFIG_INPUT_POWERMATE=y
CONFIG_INPUT_YEALINK=y
CONFIG_INPUT_CM109=y
CONFIG_INPUT_REGULATOR_HAPTIC=y
CONFIG_INPUT_RETU_PWRBUTTON=y
CONFIG_INPUT_TPS65218_PWRBUTTON=y
CONFIG_INPUT_AXP20X_PEK=y
CONFIG_INPUT_TWL4030_PWRBUTTON=y
CONFIG_INPUT_TWL4030_VIBRA=y
CONFIG_INPUT_TWL6040_VIBRA=y
CONFIG_INPUT_UINPUT=y
CONFIG_INPUT_PALMAS_PWRBUTTON=y
CONFIG_INPUT_PCF50633_PMU=y
CONFIG_INPUT_PCF8574=y
CONFIG_INPUT_PWM_BEEPER=y
CONFIG_INPUT_PWM_VIBRA=y
CONFIG_INPUT_RK805_PWRKEY=y
CONFIG_INPUT_GPIO_ROTARY_ENCODER=y
CONFIG_INPUT_DA7280_HAPTICS=y
CONFIG_INPUT_DA9052_ONKEY=y
CONFIG_INPUT_DA9055_ONKEY=y
CONFIG_INPUT_DA9063_ONKEY=y
CONFIG_INPUT_WM831X_ON=y
CONFIG_INPUT_PCAP=y
CONFIG_INPUT_ADXL34X=y
CONFIG_INPUT_ADXL34X_I2C=y
CONFIG_INPUT_ADXL34X_SPI=y
CONFIG_INPUT_IMS_PCU=y
CONFIG_INPUT_IQS269A=y
CONFIG_INPUT_IQS626A=y
CONFIG_INPUT_IQS7222=y
CONFIG_INPUT_CMA3000=y
CONFIG_INPUT_CMA3000_I2C=y
CONFIG_INPUT_XEN_KBDDEV_FRONTEND=y
CONFIG_INPUT_IDEAPAD_SLIDEBAR=y
CONFIG_INPUT_SOC_BUTTON_ARRAY=y
CONFIG_INPUT_DRV260X_HAPTICS=y
CONFIG_INPUT_DRV2665_HAPTICS=y
CONFIG_INPUT_DRV2667_HAPTICS=y
CONFIG_INPUT_RAVE_SP_PWRBUTTON=y
CONFIG_INPUT_STPMIC1_ONKEY=y
CONFIG_RMI4_CORE=y
CONFIG_RMI4_I2C=y
CONFIG_RMI4_SPI=y
CONFIG_RMI4_SMB=y
CONFIG_RMI4_F03=y
CONFIG_RMI4_F03_SERIO=y
CONFIG_RMI4_2D_SENSOR=y
CONFIG_RMI4_F11=y
CONFIG_RMI4_F12=y
CONFIG_RMI4_F30=y
CONFIG_RMI4_F34=y
CONFIG_RMI4_F3A=y
CONFIG_RMI4_F54=y
CONFIG_RMI4_F55=y

#
# Hardware I/O ports
#
CONFIG_SERIO=y
CONFIG_ARCH_MIGHT_HAVE_PC_SERIO=y
CONFIG_SERIO_I8042=y
CONFIG_SERIO_SERPORT=y
CONFIG_SERIO_CT82C710=y
CONFIG_SERIO_PARKBD=y
CONFIG_SERIO_PCIPS2=y
CONFIG_SERIO_LIBPS2=y
CONFIG_SERIO_RAW=y
CONFIG_SERIO_ALTERA_PS2=y
CONFIG_SERIO_PS2MULT=y
CONFIG_SERIO_ARC_PS2=y
CONFIG_SERIO_APBPS2=y
CONFIG_HYPERV_KEYBOARD=y
CONFIG_SERIO_GPIO_PS2=y
CONFIG_USERIO=y
CONFIG_GAMEPORT=y
CONFIG_GAMEPORT_NS558=y
CONFIG_GAMEPORT_L4=y
CONFIG_GAMEPORT_EMU10K1=y
CONFIG_GAMEPORT_FM801=y
# end of Hardware I/O ports
# end of Input device support

#
# Character devices
#
CONFIG_TTY=y
CONFIG_VT=y
CONFIG_CONSOLE_TRANSLATIONS=y
CONFIG_VT_CONSOLE=y
CONFIG_VT_CONSOLE_SLEEP=y
CONFIG_HW_CONSOLE=y
CONFIG_VT_HW_CONSOLE_BINDING=y
CONFIG_UNIX98_PTYS=y
CONFIG_LEGACY_PTYS=y
CONFIG_LEGACY_PTY_COUNT=256
CONFIG_LDISC_AUTOLOAD=y

#
# Serial drivers
#
CONFIG_SERIAL_EARLYCON=y
CONFIG_SERIAL_8250=y
CONFIG_SERIAL_8250_DEPRECATED_OPTIONS=y
CONFIG_SERIAL_8250_PNP=y
CONFIG_SERIAL_8250_16550A_VARIANTS=y
CONFIG_SERIAL_8250_FINTEK=y
CONFIG_SERIAL_8250_CONSOLE=y
CONFIG_SERIAL_8250_DMA=y
CONFIG_SERIAL_8250_PCI=y
CONFIG_SERIAL_8250_EXAR=y
CONFIG_SERIAL_8250_CS=y
CONFIG_SERIAL_8250_MEN_MCB=y
CONFIG_SERIAL_8250_NR_UARTS=4
CONFIG_SERIAL_8250_RUNTIME_UARTS=4
CONFIG_SERIAL_8250_EXTENDED=y
CONFIG_SERIAL_8250_MANY_PORTS=y
CONFIG_SERIAL_8250_SHARE_IRQ=y
CONFIG_SERIAL_8250_DETECT_IRQ=y
CONFIG_SERIAL_8250_RSA=y
CONFIG_SERIAL_8250_DWLIB=y
CONFIG_SERIAL_8250_DW=y
CONFIG_SERIAL_8250_RT288X=y
CONFIG_SERIAL_8250_LPSS=y
CONFIG_SERIAL_8250_MID=y
CONFIG_SERIAL_8250_PERICOM=y
CONFIG_SERIAL_OF_PLATFORM=y

#
# Non-8250 serial port support
#
CONFIG_SERIAL_KGDB_NMI=y
CONFIG_SERIAL_MAX3100=y
CONFIG_SERIAL_MAX310X=y
CONFIG_SERIAL_UARTLITE=y
CONFIG_SERIAL_UARTLITE_CONSOLE=y
CONFIG_SERIAL_UARTLITE_NR_UARTS=1
CONFIG_SERIAL_CORE=y
CONFIG_SERIAL_CORE_CONSOLE=y
CONFIG_CONSOLE_POLL=y
CONFIG_SERIAL_JSM=y
CONFIG_SERIAL_SIFIVE=y
CONFIG_SERIAL_SIFIVE_CONSOLE=y
CONFIG_SERIAL_LANTIQ=y
CONFIG_SERIAL_LANTIQ_CONSOLE=y
CONFIG_SERIAL_SCCNXP=y
CONFIG_SERIAL_SCCNXP_CONSOLE=y
CONFIG_SERIAL_SC16IS7XX_CORE=y
CONFIG_SERIAL_SC16IS7XX=y
CONFIG_SERIAL_SC16IS7XX_I2C=y
CONFIG_SERIAL_SC16IS7XX_SPI=y
CONFIG_SERIAL_ALTERA_JTAGUART=y
CONFIG_SERIAL_ALTERA_JTAGUART_CONSOLE=y
CONFIG_SERIAL_ALTERA_JTAGUART_CONSOLE_BYPASS=y
CONFIG_SERIAL_ALTERA_UART=y
CONFIG_SERIAL_ALTERA_UART_MAXPORTS=4
CONFIG_SERIAL_ALTERA_UART_BAUDRATE=115200
CONFIG_SERIAL_ALTERA_UART_CONSOLE=y
CONFIG_SERIAL_XILINX_PS_UART=y
CONFIG_SERIAL_XILINX_PS_UART_CONSOLE=y
CONFIG_SERIAL_ARC=y
CONFIG_SERIAL_ARC_CONSOLE=y
CONFIG_SERIAL_ARC_NR_PORTS=1
CONFIG_SERIAL_RP2=y
CONFIG_SERIAL_RP2_NR_UARTS=32
CONFIG_SERIAL_FSL_LPUART=y
CONFIG_SERIAL_FSL_LPUART_CONSOLE=y
CONFIG_SERIAL_FSL_LINFLEXUART=y
CONFIG_SERIAL_FSL_LINFLEXUART_CONSOLE=y
CONFIG_SERIAL_CONEXANT_DIGICOLOR=y
CONFIG_SERIAL_CONEXANT_DIGICOLOR_CONSOLE=y
CONFIG_SERIAL_MEN_Z135=y
CONFIG_SERIAL_SPRD=y
CONFIG_SERIAL_SPRD_CONSOLE=y
CONFIG_SERIAL_LITEUART=y
CONFIG_SERIAL_LITEUART_MAX_PORTS=1
CONFIG_SERIAL_LITEUART_CONSOLE=y
# end of Serial drivers

CONFIG_SERIAL_MCTRL_GPIO=y
CONFIG_SERIAL_NONSTANDARD=y
CONFIG_MOXA_INTELLIO=y
CONFIG_MOXA_SMARTIO=y
CONFIG_SYNCLINK_GT=y
CONFIG_N_HDLC=y
CONFIG_GOLDFISH_TTY=y
CONFIG_GOLDFISH_TTY_EARLY_CONSOLE=y
CONFIG_N_GSM=y
CONFIG_NOZOMI=y
CONFIG_NULL_TTY=y
CONFIG_HVC_DRIVER=y
CONFIG_HVC_IRQ=y
CONFIG_HVC_XEN=y
CONFIG_HVC_XEN_FRONTEND=y
CONFIG_RPMSG_TTY=y
CONFIG_SERIAL_DEV_BUS=y
CONFIG_SERIAL_DEV_CTRL_TTYPORT=y
CONFIG_TTY_PRINTK=y
CONFIG_TTY_PRINTK_LEVEL=6
CONFIG_PRINTER=y
CONFIG_LP_CONSOLE=y
CONFIG_PPDEV=y
CONFIG_VIRTIO_CONSOLE=y
CONFIG_IPMI_HANDLER=y
CONFIG_IPMI_DMI_DECODE=y
CONFIG_IPMI_PLAT_DATA=y
CONFIG_IPMI_PANIC_EVENT=y
CONFIG_IPMI_PANIC_STRING=y
CONFIG_IPMI_DEVICE_INTERFACE=y
CONFIG_IPMI_SI=y
CONFIG_IPMI_SSIF=y
CONFIG_IPMI_IPMB=y
CONFIG_IPMI_WATCHDOG=y
CONFIG_IPMI_POWEROFF=y
CONFIG_IPMB_DEVICE_INTERFACE=y
CONFIG_HW_RANDOM=y
CONFIG_HW_RANDOM_TIMERIOMEM=y
CONFIG_HW_RANDOM_INTEL=y
CONFIG_HW_RANDOM_AMD=y
CONFIG_HW_RANDOM_BA431=y
CONFIG_HW_RANDOM_VIA=y
CONFIG_HW_RANDOM_VIRTIO=y
CONFIG_HW_RANDOM_CCTRNG=y
CONFIG_HW_RANDOM_XIPHERA=y
CONFIG_APPLICOM=y

#
# PCMCIA character devices
#
CONFIG_SYNCLINK_CS=y
CONFIG_CARDMAN_4000=y
CONFIG_CARDMAN_4040=y
CONFIG_SCR24X=y
CONFIG_IPWIRELESS=y
# end of PCMCIA character devices

CONFIG_MWAVE=y
CONFIG_DEVMEM=y
CONFIG_NVRAM=y
CONFIG_DEVPORT=y
CONFIG_HPET=y
CONFIG_HPET_MMAP=y
CONFIG_HPET_MMAP_DEFAULT=y
CONFIG_HANGCHECK_TIMER=y
CONFIG_UV_MMTIMER=y
CONFIG_TCG_TPM=y
CONFIG_HW_RANDOM_TPM=y
CONFIG_TCG_TIS_CORE=y
CONFIG_TCG_TIS=y
CONFIG_TCG_TIS_SPI=y
CONFIG_TCG_TIS_SPI_CR50=y
CONFIG_TCG_TIS_I2C=y
CONFIG_TCG_TIS_I2C_CR50=y
CONFIG_TCG_TIS_I2C_ATMEL=y
CONFIG_TCG_TIS_I2C_INFINEON=y
CONFIG_TCG_TIS_I2C_NUVOTON=y
CONFIG_TCG_NSC=y
CONFIG_TCG_ATMEL=y
CONFIG_TCG_INFINEON=y
CONFIG_TCG_XEN=y
CONFIG_TCG_CRB=y
CONFIG_TCG_VTPM_PROXY=y
CONFIG_TCG_TIS_ST33ZP24=y
CONFIG_TCG_TIS_ST33ZP24_I2C=y
CONFIG_TCG_TIS_ST33ZP24_SPI=y
CONFIG_TELCLOCK=y
CONFIG_XILLYBUS_CLASS=y
CONFIG_XILLYBUS=y
CONFIG_XILLYBUS_PCIE=y
CONFIG_XILLYBUS_OF=y
CONFIG_XILLYUSB=y
CONFIG_RANDOM_TRUST_CPU=y
CONFIG_RANDOM_TRUST_BOOTLOADER=y
# end of Character devices

#
# I2C support
#
CONFIG_I2C=y
CONFIG_ACPI_I2C_OPREGION=y
CONFIG_I2C_BOARDINFO=y
CONFIG_I2C_COMPAT=y
CONFIG_I2C_CHARDEV=y
CONFIG_I2C_MUX=y

#
# Multiplexer I2C Chip support
#
CONFIG_I2C_ARB_GPIO_CHALLENGE=y
CONFIG_I2C_MUX_GPIO=y
CONFIG_I2C_MUX_GPMUX=y
CONFIG_I2C_MUX_LTC4306=y
CONFIG_I2C_MUX_PCA9541=y
CONFIG_I2C_MUX_PCA954x=y
CONFIG_I2C_MUX_PINCTRL=y
CONFIG_I2C_MUX_REG=y
CONFIG_I2C_DEMUX_PINCTRL=y
CONFIG_I2C_MUX_MLXCPLD=y
# end of Multiplexer I2C Chip support

CONFIG_I2C_HELPER_AUTO=y
CONFIG_I2C_SMBUS=y
CONFIG_I2C_ALGOBIT=y
CONFIG_I2C_ALGOPCA=y

#
# I2C Hardware Bus support
#

#
# PC SMBus host controller drivers
#
CONFIG_I2C_CCGX_UCSI=y
CONFIG_I2C_ALI1535=y
CONFIG_I2C_ALI1563=y
CONFIG_I2C_ALI15X3=y
CONFIG_I2C_AMD756=y
CONFIG_I2C_AMD756_S4882=y
CONFIG_I2C_AMD8111=y
CONFIG_I2C_AMD_MP2=y
CONFIG_I2C_I801=y
CONFIG_I2C_ISCH=y
CONFIG_I2C_ISMT=y
CONFIG_I2C_PIIX4=y
CONFIG_I2C_CHT_WC=y
CONFIG_I2C_NFORCE2=y
CONFIG_I2C_NFORCE2_S4985=y
CONFIG_I2C_NVIDIA_GPU=y
CONFIG_I2C_SIS5595=y
CONFIG_I2C_SIS630=y
CONFIG_I2C_SIS96X=y
CONFIG_I2C_VIA=y
CONFIG_I2C_VIAPRO=y

#
# ACPI drivers
#
CONFIG_I2C_SCMI=y

#
# I2C system bus drivers (mostly embedded / system-on-chip)
#
CONFIG_I2C_CBUS_GPIO=y
CONFIG_I2C_DESIGNWARE_CORE=y
CONFIG_I2C_DESIGNWARE_SLAVE=y
CONFIG_I2C_DESIGNWARE_PLATFORM=y
CONFIG_I2C_DESIGNWARE_AMDPSP=y
CONFIG_I2C_DESIGNWARE_BAYTRAIL=y
CONFIG_I2C_DESIGNWARE_PCI=y
CONFIG_I2C_EMEV2=y
CONFIG_I2C_GPIO=y
CONFIG_I2C_GPIO_FAULT_INJECTOR=y
CONFIG_I2C_KEMPLD=y
CONFIG_I2C_OCORES=y
CONFIG_I2C_PCA_PLATFORM=y
CONFIG_I2C_RK3X=y
CONFIG_I2C_SIMTEC=y
CONFIG_I2C_XILINX=y

#
# External I2C/SMBus adapter drivers
#
CONFIG_I2C_DIOLAN_U2C=y
CONFIG_I2C_DLN2=y
CONFIG_I2C_CP2615=y
CONFIG_I2C_PARPORT=y
CONFIG_I2C_ROBOTFUZZ_OSIF=y
CONFIG_I2C_TAOS_EVM=y
CONFIG_I2C_TINY_USB=y
CONFIG_I2C_VIPERBOARD=y

#
# Other I2C/SMBus bus drivers
#
CONFIG_I2C_MLXCPLD=y
CONFIG_I2C_CROS_EC_TUNNEL=y
CONFIG_I2C_FSI=y
CONFIG_I2C_VIRTIO=y
# end of I2C Hardware Bus support

CONFIG_I2C_STUB=m
CONFIG_I2C_SLAVE=y
CONFIG_I2C_SLAVE_EEPROM=y
CONFIG_I2C_SLAVE_TESTUNIT=y
CONFIG_I2C_DEBUG_CORE=y
CONFIG_I2C_DEBUG_ALGO=y
CONFIG_I2C_DEBUG_BUS=y
# end of I2C support

CONFIG_I3C=y
CONFIG_CDNS_I3C_MASTER=y
CONFIG_DW_I3C_MASTER=y
CONFIG_SVC_I3C_MASTER=y
CONFIG_MIPI_I3C_HCI=y
CONFIG_SPI=y
CONFIG_SPI_DEBUG=y
CONFIG_SPI_MASTER=y
CONFIG_SPI_MEM=y

#
# SPI Master Controller Drivers
#
CONFIG_SPI_ALTERA=y
CONFIG_SPI_ALTERA_CORE=y
CONFIG_SPI_ALTERA_DFL=y
CONFIG_SPI_AXI_SPI_ENGINE=y
CONFIG_SPI_BITBANG=y
CONFIG_SPI_BUTTERFLY=y
CONFIG_SPI_CADENCE=y
CONFIG_SPI_CADENCE_QUADSPI=y
CONFIG_SPI_CADENCE_XSPI=y
CONFIG_SPI_DESIGNWARE=y
CONFIG_SPI_DW_DMA=y
CONFIG_SPI_DW_PCI=y
CONFIG_SPI_DW_MMIO=y
CONFIG_SPI_DLN2=y
CONFIG_SPI_FSI=y
CONFIG_SPI_NXP_FLEXSPI=y
CONFIG_SPI_GPIO=y
CONFIG_SPI_INTEL=y
CONFIG_SPI_INTEL_PCI=y
CONFIG_SPI_INTEL_PLATFORM=y
CONFIG_SPI_LM70_LLP=y
CONFIG_SPI_FSL_LIB=y
CONFIG_SPI_FSL_SPI=y
CONFIG_SPI_MICROCHIP_CORE=y
CONFIG_SPI_LANTIQ_SSC=y
CONFIG_SPI_OC_TINY=y
CONFIG_SPI_PXA2XX=y
CONFIG_SPI_PXA2XX_PCI=y
CONFIG_SPI_ROCKCHIP=y
CONFIG_SPI_SC18IS602=y
CONFIG_SPI_SIFIVE=y
CONFIG_SPI_MXIC=y
CONFIG_SPI_XCOMM=y
CONFIG_SPI_XILINX=y
CONFIG_SPI_ZYNQMP_GQSPI=y
CONFIG_SPI_AMD=y

#
# SPI Multiplexer support
#
CONFIG_SPI_MUX=y

#
# SPI Protocol Masters
#
CONFIG_SPI_SPIDEV=y
CONFIG_SPI_LOOPBACK_TEST=m
CONFIG_SPI_TLE62X0=y
CONFIG_SPI_SLAVE=y
CONFIG_SPI_SLAVE_TIME=y
CONFIG_SPI_SLAVE_SYSTEM_CONTROL=y
CONFIG_SPI_DYNAMIC=y
CONFIG_SPMI=y
CONFIG_SPMI_HISI3670=y
CONFIG_HSI=y
CONFIG_HSI_BOARDINFO=y

#
# HSI controllers
#

#
# HSI clients
#
CONFIG_HSI_CHAR=y
CONFIG_PPS=y
CONFIG_PPS_DEBUG=y

#
# PPS clients support
#
CONFIG_PPS_CLIENT_KTIMER=y
CONFIG_PPS_CLIENT_LDISC=y
CONFIG_PPS_CLIENT_PARPORT=y
CONFIG_PPS_CLIENT_GPIO=y

#
# PPS generators support
#

#
# PTP clock support
#
CONFIG_PTP_1588_CLOCK=y
CONFIG_PTP_1588_CLOCK_OPTIONAL=y
CONFIG_DP83640_PHY=y
CONFIG_PTP_1588_CLOCK_INES=y
CONFIG_PTP_1588_CLOCK_KVM=y
CONFIG_PTP_1588_CLOCK_IDT82P33=y
CONFIG_PTP_1588_CLOCK_IDTCM=y
CONFIG_PTP_1588_CLOCK_VMW=y
CONFIG_PTP_1588_CLOCK_OCP=y
# end of PTP clock support

CONFIG_PINCTRL=y
CONFIG_GENERIC_PINCTRL_GROUPS=y
CONFIG_PINMUX=y
CONFIG_GENERIC_PINMUX_FUNCTIONS=y
CONFIG_PINCONF=y
CONFIG_GENERIC_PINCONF=y
CONFIG_DEBUG_PINCTRL=y
CONFIG_PINCTRL_AMD=y
CONFIG_PINCTRL_AS3722=y
CONFIG_PINCTRL_AXP209=y
CONFIG_PINCTRL_DA9062=y
CONFIG_PINCTRL_EQUILIBRIUM=y
CONFIG_PINCTRL_MAX77620=y
CONFIG_PINCTRL_MCP23S08_I2C=y
CONFIG_PINCTRL_MCP23S08_SPI=y
CONFIG_PINCTRL_MCP23S08=y
CONFIG_PINCTRL_MICROCHIP_SGPIO=y
CONFIG_PINCTRL_OCELOT=y
CONFIG_PINCTRL_PALMAS=y
CONFIG_PINCTRL_RK805=y
CONFIG_PINCTRL_SINGLE=y
CONFIG_PINCTRL_STMFX=y
CONFIG_PINCTRL_SX150X=y
CONFIG_PINCTRL_LOCHNAGAR=y
CONFIG_PINCTRL_MADERA=y
CONFIG_PINCTRL_CS47L15=y
CONFIG_PINCTRL_CS47L35=y
CONFIG_PINCTRL_CS47L85=y
CONFIG_PINCTRL_CS47L90=y
CONFIG_PINCTRL_CS47L92=y

#
# Intel pinctrl drivers
#
CONFIG_PINCTRL_BAYTRAIL=y
CONFIG_PINCTRL_CHERRYVIEW=y
CONFIG_PINCTRL_LYNXPOINT=y
CONFIG_PINCTRL_MERRIFIELD=y
CONFIG_PINCTRL_INTEL=y
CONFIG_PINCTRL_ALDERLAKE=y
CONFIG_PINCTRL_BROXTON=y
CONFIG_PINCTRL_CANNONLAKE=y
CONFIG_PINCTRL_CEDARFORK=y
CONFIG_PINCTRL_DENVERTON=y
CONFIG_PINCTRL_ELKHARTLAKE=y
CONFIG_PINCTRL_EMMITSBURG=y
CONFIG_PINCTRL_GEMINILAKE=y
CONFIG_PINCTRL_ICELAKE=y
CONFIG_PINCTRL_JASPERLAKE=y
CONFIG_PINCTRL_LAKEFIELD=y
CONFIG_PINCTRL_LEWISBURG=y
CONFIG_PINCTRL_METEORLAKE=y
CONFIG_PINCTRL_SUNRISEPOINT=y
CONFIG_PINCTRL_TIGERLAKE=y
# end of Intel pinctrl drivers

#
# Renesas pinctrl drivers
#
# end of Renesas pinctrl drivers

CONFIG_GPIOLIB=y
CONFIG_GPIOLIB_FASTPATH_LIMIT=512
CONFIG_OF_GPIO=y
CONFIG_GPIO_ACPI=y
CONFIG_GPIOLIB_IRQCHIP=y
CONFIG_DEBUG_GPIO=y
CONFIG_GPIO_SYSFS=y
CONFIG_GPIO_CDEV=y
CONFIG_GPIO_CDEV_V1=y
CONFIG_GPIO_GENERIC=y
CONFIG_GPIO_MAX730X=y

#
# Memory mapped GPIO drivers
#
CONFIG_GPIO_74XX_MMIO=y
CONFIG_GPIO_ALTERA=y
CONFIG_GPIO_AMDPT=y
CONFIG_GPIO_CADENCE=y
CONFIG_GPIO_DWAPB=y
CONFIG_GPIO_EXAR=y
CONFIG_GPIO_FTGPIO010=y
CONFIG_GPIO_GENERIC_PLATFORM=y
CONFIG_GPIO_GRGPIO=y
CONFIG_GPIO_HLWD=y
CONFIG_GPIO_ICH=y
CONFIG_GPIO_LOGICVC=y
CONFIG_GPIO_MB86S7X=y
CONFIG_GPIO_MENZ127=y
CONFIG_GPIO_SIFIVE=y
CONFIG_GPIO_SIOX=y
CONFIG_GPIO_SYSCON=y
CONFIG_GPIO_VX855=y
CONFIG_GPIO_WCD934X=y
CONFIG_GPIO_XILINX=y
CONFIG_GPIO_AMD_FCH=y
# end of Memory mapped GPIO drivers

#
# Port-mapped I/O GPIO drivers
#
CONFIG_GPIO_I8255=y
CONFIG_GPIO_104_DIO_48E=y
CONFIG_GPIO_104_IDIO_16=y
CONFIG_GPIO_104_IDI_48=y
CONFIG_GPIO_F7188X=y
CONFIG_GPIO_GPIO_MM=y
CONFIG_GPIO_IT87=y
CONFIG_GPIO_SCH=y
CONFIG_GPIO_SCH311X=y
CONFIG_GPIO_WINBOND=y
CONFIG_GPIO_WS16C48=y
# end of Port-mapped I/O GPIO drivers

#
# I2C GPIO expanders
#
CONFIG_GPIO_ADP5588=y
CONFIG_GPIO_ADP5588_IRQ=y
CONFIG_GPIO_ADNP=y
CONFIG_GPIO_GW_PLD=y
CONFIG_GPIO_MAX7300=y
CONFIG_GPIO_MAX732X=y
CONFIG_GPIO_MAX732X_IRQ=y
CONFIG_GPIO_PCA953X=y
CONFIG_GPIO_PCA953X_IRQ=y
CONFIG_GPIO_PCA9570=y
CONFIG_GPIO_PCF857X=y
CONFIG_GPIO_TPIC2810=y
# end of I2C GPIO expanders

#
# MFD GPIO expanders
#
CONFIG_GPIO_ADP5520=y
CONFIG_GPIO_ARIZONA=y
CONFIG_GPIO_BD71815=y
CONFIG_GPIO_BD71828=y
CONFIG_GPIO_BD9571MWV=y
CONFIG_GPIO_CRYSTAL_COVE=y
CONFIG_GPIO_DA9052=y
CONFIG_GPIO_DA9055=y
CONFIG_GPIO_DLN2=y
CONFIG_GPIO_JANZ_TTL=y
CONFIG_GPIO_KEMPLD=y
CONFIG_GPIO_LP3943=y
CONFIG_GPIO_LP873X=y
CONFIG_GPIO_LP87565=y
CONFIG_GPIO_MADERA=y
CONFIG_GPIO_MAX77620=y
CONFIG_GPIO_MAX77650=y
CONFIG_GPIO_PALMAS=y
CONFIG_GPIO_RC5T583=y
CONFIG_GPIO_STMPE=y
CONFIG_GPIO_TC3589X=y
CONFIG_GPIO_TPS65086=y
CONFIG_GPIO_TPS65218=y
CONFIG_GPIO_TPS6586X=y
CONFIG_GPIO_TPS65910=y
CONFIG_GPIO_TPS65912=y
CONFIG_GPIO_TPS68470=y
CONFIG_GPIO_TQMX86=y
CONFIG_GPIO_TWL4030=y
CONFIG_GPIO_TWL6040=y
CONFIG_GPIO_UCB1400=y
CONFIG_GPIO_WHISKEY_COVE=y
CONFIG_GPIO_WM831X=y
CONFIG_GPIO_WM8350=y
CONFIG_GPIO_WM8994=y
# end of MFD GPIO expanders

#
# PCI GPIO expanders
#
CONFIG_GPIO_AMD8111=y
CONFIG_GPIO_MERRIFIELD=y
CONFIG_GPIO_ML_IOH=y
CONFIG_GPIO_PCI_IDIO_16=y
CONFIG_GPIO_PCIE_IDIO_24=y
CONFIG_GPIO_RDC321X=y
CONFIG_GPIO_SODAVILLE=y
# end of PCI GPIO expanders

#
# SPI GPIO expanders
#
CONFIG_GPIO_74X164=y
CONFIG_GPIO_MAX3191X=y
CONFIG_GPIO_MAX7301=y
CONFIG_GPIO_MC33880=y
CONFIG_GPIO_PISOSR=y
CONFIG_GPIO_XRA1403=y
CONFIG_GPIO_MOXTET=y
# end of SPI GPIO expanders

#
# USB GPIO expanders
#
CONFIG_GPIO_VIPERBOARD=y
# end of USB GPIO expanders

#
# Virtual GPIO drivers
#
CONFIG_GPIO_AGGREGATOR=y
CONFIG_GPIO_MOCKUP=y
CONFIG_GPIO_VIRTIO=y
CONFIG_GPIO_SIM=y
# end of Virtual GPIO drivers

CONFIG_W1=y
CONFIG_W1_CON=y

#
# 1-wire Bus Masters
#
CONFIG_W1_MASTER_MATROX=y
CONFIG_W1_MASTER_DS2490=y
CONFIG_W1_MASTER_DS2482=y
CONFIG_W1_MASTER_DS1WM=y
CONFIG_W1_MASTER_GPIO=y
CONFIG_W1_MASTER_SGI=y
# end of 1-wire Bus Masters

#
# 1-wire Slaves
#
CONFIG_W1_SLAVE_THERM=y
CONFIG_W1_SLAVE_SMEM=y
CONFIG_W1_SLAVE_DS2405=y
CONFIG_W1_SLAVE_DS2408=y
CONFIG_W1_SLAVE_DS2408_READBACK=y
CONFIG_W1_SLAVE_DS2413=y
CONFIG_W1_SLAVE_DS2406=y
CONFIG_W1_SLAVE_DS2423=y
CONFIG_W1_SLAVE_DS2805=y
CONFIG_W1_SLAVE_DS2430=y
CONFIG_W1_SLAVE_DS2431=y
CONFIG_W1_SLAVE_DS2433=y
CONFIG_W1_SLAVE_DS2433_CRC=y
CONFIG_W1_SLAVE_DS2438=y
CONFIG_W1_SLAVE_DS250X=y
CONFIG_W1_SLAVE_DS2780=y
CONFIG_W1_SLAVE_DS2781=y
CONFIG_W1_SLAVE_DS28E04=y
CONFIG_W1_SLAVE_DS28E17=y
# end of 1-wire Slaves

CONFIG_POWER_RESET=y
CONFIG_POWER_RESET_AS3722=y
CONFIG_POWER_RESET_ATC260X=y
CONFIG_POWER_RESET_GPIO=y
CONFIG_POWER_RESET_GPIO_RESTART=y
CONFIG_POWER_RESET_LTC2952=y
CONFIG_POWER_RESET_MT6323=y
CONFIG_POWER_RESET_REGULATOR=y
CONFIG_POWER_RESET_RESTART=y
CONFIG_POWER_RESET_TPS65086=y
CONFIG_POWER_RESET_SYSCON=y
CONFIG_POWER_RESET_SYSCON_POWEROFF=y
CONFIG_REBOOT_MODE=y
CONFIG_SYSCON_REBOOT_MODE=y
CONFIG_NVMEM_REBOOT_MODE=y
CONFIG_POWER_SUPPLY=y
CONFIG_POWER_SUPPLY_DEBUG=y
CONFIG_POWER_SUPPLY_HWMON=y
CONFIG_PDA_POWER=y
CONFIG_GENERIC_ADC_BATTERY=y
CONFIG_IP5XXX_POWER=y
CONFIG_MAX8925_POWER=y
CONFIG_WM831X_BACKUP=y
CONFIG_WM831X_POWER=y
CONFIG_WM8350_POWER=y
CONFIG_TEST_POWER=y
CONFIG_BATTERY_88PM860X=y
CONFIG_CHARGER_ADP5061=y
CONFIG_BATTERY_ACT8945A=y
CONFIG_BATTERY_CPCAP=y
CONFIG_BATTERY_CW2015=y
CONFIG_BATTERY_DS2760=y
CONFIG_BATTERY_DS2780=y
CONFIG_BATTERY_DS2781=y
CONFIG_BATTERY_DS2782=y
CONFIG_BATTERY_SAMSUNG_SDI=y
CONFIG_BATTERY_WM97XX=y
CONFIG_BATTERY_SBS=y
CONFIG_CHARGER_SBS=y
CONFIG_MANAGER_SBS=y
CONFIG_BATTERY_BQ27XXX=y
CONFIG_BATTERY_BQ27XXX_I2C=y
CONFIG_BATTERY_BQ27XXX_HDQ=y
CONFIG_BATTERY_BQ27XXX_DT_UPDATES_NVM=y
CONFIG_BATTERY_DA9030=y
CONFIG_BATTERY_DA9052=y
CONFIG_CHARGER_DA9150=y
CONFIG_BATTERY_DA9150=y
CONFIG_CHARGER_AXP20X=y
CONFIG_BATTERY_AXP20X=y
CONFIG_AXP20X_POWER=y
CONFIG_AXP288_CHARGER=y
CONFIG_AXP288_FUEL_GAUGE=y
CONFIG_BATTERY_MAX17040=y
CONFIG_BATTERY_MAX17042=y
CONFIG_BATTERY_MAX1721X=y
CONFIG_BATTERY_TWL4030_MADC=y
CONFIG_CHARGER_88PM860X=y
CONFIG_CHARGER_PCF50633=y
CONFIG_BATTERY_RX51=y
CONFIG_CHARGER_ISP1704=y
CONFIG_CHARGER_MAX8903=y
CONFIG_CHARGER_TWL4030=y
CONFIG_CHARGER_LP8727=y
CONFIG_CHARGER_LP8788=y
CONFIG_CHARGER_GPIO=y
CONFIG_CHARGER_MANAGER=y
CONFIG_CHARGER_LT3651=y
CONFIG_CHARGER_LTC4162L=y
CONFIG_CHARGER_MAX14577=y
CONFIG_CHARGER_DETECTOR_MAX14656=y
CONFIG_CHARGER_MAX77650=y
CONFIG_CHARGER_MAX77693=y
CONFIG_CHARGER_MAX77976=y
CONFIG_CHARGER_MAX8997=y
CONFIG_CHARGER_MAX8998=y
CONFIG_CHARGER_MP2629=y
CONFIG_CHARGER_MT6360=y
CONFIG_CHARGER_BQ2415X=y
CONFIG_CHARGER_BQ24190=y
CONFIG_CHARGER_BQ24257=y
CONFIG_CHARGER_BQ24735=y
CONFIG_CHARGER_BQ2515X=y
CONFIG_CHARGER_BQ25890=y
CONFIG_CHARGER_BQ25980=y
CONFIG_CHARGER_BQ256XX=y
CONFIG_CHARGER_SMB347=y
CONFIG_CHARGER_TPS65090=y
CONFIG_CHARGER_TPS65217=y
CONFIG_BATTERY_GAUGE_LTC2941=y
CONFIG_BATTERY_GOLDFISH=y
CONFIG_BATTERY_RT5033=y
CONFIG_CHARGER_RT9455=y
CONFIG_CHARGER_CROS_USBPD=y
CONFIG_CHARGER_CROS_PCHG=y
CONFIG_CHARGER_UCS1002=y
CONFIG_CHARGER_BD99954=y
CONFIG_CHARGER_WILCO=y
CONFIG_RN5T618_POWER=y
CONFIG_BATTERY_SURFACE=y
CONFIG_CHARGER_SURFACE=y
CONFIG_BATTERY_UG3105=y
CONFIG_HWMON=y
CONFIG_HWMON_VID=y
CONFIG_HWMON_DEBUG_CHIP=y

#
# Native drivers
#
CONFIG_SENSORS_ABITUGURU=y
CONFIG_SENSORS_ABITUGURU3=y
CONFIG_SENSORS_AD7314=y
CONFIG_SENSORS_AD7414=y
CONFIG_SENSORS_AD7418=y
CONFIG_SENSORS_ADM1025=y
CONFIG_SENSORS_ADM1026=y
CONFIG_SENSORS_ADM1029=y
CONFIG_SENSORS_ADM1031=y
CONFIG_SENSORS_ADM1177=y
CONFIG_SENSORS_ADM9240=y
CONFIG_SENSORS_ADT7X10=y
CONFIG_SENSORS_ADT7310=y
CONFIG_SENSORS_ADT7410=y
CONFIG_SENSORS_ADT7411=y
CONFIG_SENSORS_ADT7462=y
CONFIG_SENSORS_ADT7470=y
CONFIG_SENSORS_ADT7475=y
CONFIG_SENSORS_AHT10=y
CONFIG_SENSORS_AQUACOMPUTER_D5NEXT=y
CONFIG_SENSORS_AS370=y
CONFIG_SENSORS_ASC7621=y
CONFIG_SENSORS_AXI_FAN_CONTROL=y
CONFIG_SENSORS_K8TEMP=y
CONFIG_SENSORS_K10TEMP=y
CONFIG_SENSORS_FAM15H_POWER=y
CONFIG_SENSORS_APPLESMC=y
CONFIG_SENSORS_ASB100=y
CONFIG_SENSORS_ASPEED=y
CONFIG_SENSORS_ATXP1=y
CONFIG_SENSORS_CORSAIR_CPRO=y
CONFIG_SENSORS_CORSAIR_PSU=y
CONFIG_SENSORS_DRIVETEMP=y
CONFIG_SENSORS_DS620=y
CONFIG_SENSORS_DS1621=y
CONFIG_SENSORS_DELL_SMM=y
CONFIG_I8K=y
CONFIG_SENSORS_DA9052_ADC=y
CONFIG_SENSORS_DA9055=y
CONFIG_SENSORS_I5K_AMB=y
CONFIG_SENSORS_F71805F=y
CONFIG_SENSORS_F71882FG=y
CONFIG_SENSORS_F75375S=y
CONFIG_SENSORS_GSC=y
CONFIG_SENSORS_MC13783_ADC=y
CONFIG_SENSORS_FSCHMD=y
CONFIG_SENSORS_FTSTEUTATES=y
CONFIG_SENSORS_GL518SM=y
CONFIG_SENSORS_GL520SM=y
CONFIG_SENSORS_G760A=y
CONFIG_SENSORS_G762=y
CONFIG_SENSORS_GPIO_FAN=y
CONFIG_SENSORS_HIH6130=y
CONFIG_SENSORS_IBMAEM=y
CONFIG_SENSORS_IBMPEX=y
CONFIG_SENSORS_IIO_HWMON=y
CONFIG_SENSORS_I5500=y
CONFIG_SENSORS_CORETEMP=y
CONFIG_SENSORS_IT87=y
CONFIG_SENSORS_JC42=y
CONFIG_SENSORS_POWR1220=y
CONFIG_SENSORS_LINEAGE=y
CONFIG_SENSORS_LOCHNAGAR=y
CONFIG_SENSORS_LTC2945=y
CONFIG_SENSORS_LTC2947=y
CONFIG_SENSORS_LTC2947_I2C=y
CONFIG_SENSORS_LTC2947_SPI=y
CONFIG_SENSORS_LTC2990=y
CONFIG_SENSORS_LTC2992=y
CONFIG_SENSORS_LTC4151=y
CONFIG_SENSORS_LTC4215=y
CONFIG_SENSORS_LTC4222=y
CONFIG_SENSORS_LTC4245=y
CONFIG_SENSORS_LTC4260=y
CONFIG_SENSORS_LTC4261=y
CONFIG_SENSORS_MAX1111=y
CONFIG_SENSORS_MAX127=y
CONFIG_SENSORS_MAX16065=y
CONFIG_SENSORS_MAX1619=y
CONFIG_SENSORS_MAX1668=y
CONFIG_SENSORS_MAX197=y
CONFIG_SENSORS_MAX31722=y
CONFIG_SENSORS_MAX31730=y
CONFIG_SENSORS_MAX6620=y
CONFIG_SENSORS_MAX6621=y
CONFIG_SENSORS_MAX6639=y
CONFIG_SENSORS_MAX6650=y
CONFIG_SENSORS_MAX6697=y
CONFIG_SENSORS_MAX31790=y
CONFIG_SENSORS_MCP3021=y
CONFIG_SENSORS_MLXREG_FAN=y
CONFIG_SENSORS_TC654=y
CONFIG_SENSORS_TPS23861=y
CONFIG_SENSORS_MENF21BMC_HWMON=y
CONFIG_SENSORS_MR75203=y
CONFIG_SENSORS_ADCXX=y
CONFIG_SENSORS_LM63=y
CONFIG_SENSORS_LM70=y
CONFIG_SENSORS_LM73=y
CONFIG_SENSORS_LM75=y
CONFIG_SENSORS_LM77=y
CONFIG_SENSORS_LM78=y
CONFIG_SENSORS_LM80=y
CONFIG_SENSORS_LM83=y
CONFIG_SENSORS_LM85=y
CONFIG_SENSORS_LM87=y
CONFIG_SENSORS_LM90=y
CONFIG_SENSORS_LM92=y
CONFIG_SENSORS_LM93=y
CONFIG_SENSORS_LM95234=y
CONFIG_SENSORS_LM95241=y
CONFIG_SENSORS_LM95245=y
CONFIG_SENSORS_PC87360=y
CONFIG_SENSORS_PC87427=y
CONFIG_SENSORS_NTC_THERMISTOR=y
CONFIG_SENSORS_NCT6683=y
CONFIG_SENSORS_NCT6775_CORE=y
CONFIG_SENSORS_NCT6775=y
CONFIG_SENSORS_NCT6775_I2C=y
CONFIG_SENSORS_NCT7802=y
CONFIG_SENSORS_NCT7904=y
CONFIG_SENSORS_NPCM7XX=y
CONFIG_SENSORS_NZXT_KRAKEN2=y
CONFIG_SENSORS_NZXT_SMART2=y
CONFIG_SENSORS_PCF8591=y
CONFIG_SENSORS_PECI_CPUTEMP=y
CONFIG_SENSORS_PECI_DIMMTEMP=y
CONFIG_SENSORS_PECI=y
CONFIG_PMBUS=y
CONFIG_SENSORS_PMBUS=y
CONFIG_SENSORS_ADM1266=y
CONFIG_SENSORS_ADM1275=y
CONFIG_SENSORS_BEL_PFE=y
CONFIG_SENSORS_BPA_RS600=y
CONFIG_SENSORS_DELTA_AHE50DC_FAN=y
CONFIG_SENSORS_FSP_3Y=y
CONFIG_SENSORS_IBM_CFFPS=y
CONFIG_SENSORS_DPS920AB=y
CONFIG_SENSORS_INSPUR_IPSPS=y
CONFIG_SENSORS_IR35221=y
CONFIG_SENSORS_IR36021=y
CONFIG_SENSORS_IR38064=y
CONFIG_SENSORS_IR38064_REGULATOR=y
CONFIG_SENSORS_IRPS5401=y
CONFIG_SENSORS_ISL68137=y
CONFIG_SENSORS_LM25066=y
CONFIG_SENSORS_LM25066_REGULATOR=y
CONFIG_SENSORS_LT7182S=y
CONFIG_SENSORS_LTC2978=y
CONFIG_SENSORS_LTC2978_REGULATOR=y
CONFIG_SENSORS_LTC3815=y
CONFIG_SENSORS_MAX15301=y
CONFIG_SENSORS_MAX16064=y
CONFIG_SENSORS_MAX16601=y
CONFIG_SENSORS_MAX20730=y
CONFIG_SENSORS_MAX20751=y
CONFIG_SENSORS_MAX31785=y
CONFIG_SENSORS_MAX34440=y
CONFIG_SENSORS_MAX8688=y
CONFIG_SENSORS_MP2888=y
CONFIG_SENSORS_MP2975=y
CONFIG_SENSORS_MP5023=y
CONFIG_SENSORS_PIM4328=y
CONFIG_SENSORS_PLI1209BC=y
CONFIG_SENSORS_PLI1209BC_REGULATOR=y
CONFIG_SENSORS_PM6764TR=y
CONFIG_SENSORS_PXE1610=y
CONFIG_SENSORS_Q54SJ108A2=y
CONFIG_SENSORS_STPDDC60=y
CONFIG_SENSORS_TPS40422=y
CONFIG_SENSORS_TPS53679=y
CONFIG_SENSORS_UCD9000=y
CONFIG_SENSORS_UCD9200=y
CONFIG_SENSORS_XDPE152=y
CONFIG_SENSORS_XDPE122=y
CONFIG_SENSORS_XDPE122_REGULATOR=y
CONFIG_SENSORS_ZL6100=y
CONFIG_SENSORS_PWM_FAN=y
CONFIG_SENSORS_SBTSI=y
CONFIG_SENSORS_SBRMI=y
CONFIG_SENSORS_SHT15=y
CONFIG_SENSORS_SHT21=y
CONFIG_SENSORS_SHT3x=y
CONFIG_SENSORS_SHT4x=y
CONFIG_SENSORS_SHTC1=y
CONFIG_SENSORS_SIS5595=y
CONFIG_SENSORS_SY7636A=y
CONFIG_SENSORS_DME1737=y
CONFIG_SENSORS_EMC1403=y
CONFIG_SENSORS_EMC2103=y
CONFIG_SENSORS_EMC6W201=y
CONFIG_SENSORS_SMSC47M1=y
CONFIG_SENSORS_SMSC47M192=y
CONFIG_SENSORS_SMSC47B397=y
CONFIG_SENSORS_SCH56XX_COMMON=y
CONFIG_SENSORS_SCH5627=y
CONFIG_SENSORS_SCH5636=y
CONFIG_SENSORS_STTS751=y
CONFIG_SENSORS_SMM665=y
CONFIG_SENSORS_ADC128D818=y
CONFIG_SENSORS_ADS7828=y
CONFIG_SENSORS_ADS7871=y
CONFIG_SENSORS_AMC6821=y
CONFIG_SENSORS_INA209=y
CONFIG_SENSORS_INA2XX=y
CONFIG_SENSORS_INA238=y
CONFIG_SENSORS_INA3221=y
CONFIG_SENSORS_TC74=y
CONFIG_SENSORS_THMC50=y
CONFIG_SENSORS_TMP102=y
CONFIG_SENSORS_TMP103=y
CONFIG_SENSORS_TMP108=y
CONFIG_SENSORS_TMP401=y
CONFIG_SENSORS_TMP421=y
CONFIG_SENSORS_TMP464=y
CONFIG_SENSORS_TMP513=y
CONFIG_SENSORS_VIA_CPUTEMP=y
CONFIG_SENSORS_VIA686A=y
CONFIG_SENSORS_VT1211=y
CONFIG_SENSORS_VT8231=y
CONFIG_SENSORS_W83773G=y
CONFIG_SENSORS_W83781D=y
CONFIG_SENSORS_W83791D=y
CONFIG_SENSORS_W83792D=y
CONFIG_SENSORS_W83793=y
CONFIG_SENSORS_W83795=y
CONFIG_SENSORS_W83795_FANCTRL=y
CONFIG_SENSORS_W83L785TS=y
CONFIG_SENSORS_W83L786NG=y
CONFIG_SENSORS_W83627HF=y
CONFIG_SENSORS_W83627EHF=y
CONFIG_SENSORS_WM831X=y
CONFIG_SENSORS_WM8350=y
CONFIG_SENSORS_XGENE=y
CONFIG_SENSORS_INTEL_M10_BMC_HWMON=y

#
# ACPI drivers
#
CONFIG_SENSORS_ACPI_POWER=y
CONFIG_SENSORS_ATK0110=y
CONFIG_SENSORS_ASUS_WMI=y
CONFIG_SENSORS_ASUS_EC=y
CONFIG_THERMAL=y
CONFIG_THERMAL_NETLINK=y
CONFIG_THERMAL_STATISTICS=y
CONFIG_THERMAL_EMERGENCY_POWEROFF_DELAY_MS=0
CONFIG_THERMAL_HWMON=y
CONFIG_THERMAL_OF=y
CONFIG_THERMAL_WRITABLE_TRIPS=y
CONFIG_THERMAL_DEFAULT_GOV_STEP_WISE=y
# CONFIG_THERMAL_DEFAULT_GOV_FAIR_SHARE is not set
# CONFIG_THERMAL_DEFAULT_GOV_USER_SPACE is not set
# CONFIG_THERMAL_DEFAULT_GOV_POWER_ALLOCATOR is not set
CONFIG_THERMAL_GOV_FAIR_SHARE=y
CONFIG_THERMAL_GOV_STEP_WISE=y
CONFIG_THERMAL_GOV_BANG_BANG=y
CONFIG_THERMAL_GOV_USER_SPACE=y
CONFIG_THERMAL_GOV_POWER_ALLOCATOR=y
CONFIG_CPU_THERMAL=y
CONFIG_CPU_FREQ_THERMAL=y
CONFIG_CPU_IDLE_THERMAL=y
CONFIG_DEVFREQ_THERMAL=y
CONFIG_THERMAL_EMULATION=y
CONFIG_THERMAL_MMIO=y
CONFIG_MAX77620_THERMAL=y
CONFIG_DA9062_THERMAL=y

#
# Intel thermal drivers
#
CONFIG_INTEL_POWERCLAMP=y
CONFIG_X86_THERMAL_VECTOR=y
CONFIG_X86_PKG_TEMP_THERMAL=y
CONFIG_INTEL_SOC_DTS_IOSF_CORE=y
CONFIG_INTEL_SOC_DTS_THERMAL=y

#
# ACPI INT340X thermal drivers
#
CONFIG_INT340X_THERMAL=y
CONFIG_ACPI_THERMAL_REL=y
CONFIG_INT3406_THERMAL=y
CONFIG_PROC_THERMAL_MMIO_RAPL=y
# end of ACPI INT340X thermal drivers

CONFIG_INTEL_BXT_PMIC_THERMAL=y
CONFIG_INTEL_PCH_THERMAL=y
CONFIG_INTEL_TCC_COOLING=y
CONFIG_INTEL_MENLOW=y
CONFIG_INTEL_HFI_THERMAL=y
# end of Intel thermal drivers

# CONFIG_TI_SOC_THERMAL is not set
CONFIG_GENERIC_ADC_THERMAL=y
CONFIG_WATCHDOG=y
CONFIG_WATCHDOG_CORE=y
CONFIG_WATCHDOG_NOWAYOUT=y
CONFIG_WATCHDOG_HANDLE_BOOT_ENABLED=y
CONFIG_WATCHDOG_OPEN_TIMEOUT=0
CONFIG_WATCHDOG_SYSFS=y
CONFIG_WATCHDOG_HRTIMER_PRETIMEOUT=y

#
# Watchdog Pretimeout Governors
#
CONFIG_WATCHDOG_PRETIMEOUT_GOV=y
CONFIG_WATCHDOG_PRETIMEOUT_GOV_SEL=m
CONFIG_WATCHDOG_PRETIMEOUT_GOV_NOOP=y
CONFIG_WATCHDOG_PRETIMEOUT_GOV_PANIC=y
# CONFIG_WATCHDOG_PRETIMEOUT_DEFAULT_GOV_NOOP is not set
CONFIG_WATCHDOG_PRETIMEOUT_DEFAULT_GOV_PANIC=y

#
# Watchdog Device Drivers
#
CONFIG_SOFT_WATCHDOG=y
CONFIG_SOFT_WATCHDOG_PRETIMEOUT=y
CONFIG_BD957XMUF_WATCHDOG=y
CONFIG_DA9052_WATCHDOG=y
CONFIG_DA9055_WATCHDOG=y
CONFIG_DA9063_WATCHDOG=y
CONFIG_DA9062_WATCHDOG=y
CONFIG_GPIO_WATCHDOG=y
CONFIG_GPIO_WATCHDOG_ARCH_INITCALL=y
CONFIG_MENF21BMC_WATCHDOG=y
CONFIG_MENZ069_WATCHDOG=y
CONFIG_WDAT_WDT=y
CONFIG_WM831X_WATCHDOG=y
CONFIG_WM8350_WATCHDOG=y
CONFIG_XILINX_WATCHDOG=y
CONFIG_ZIIRAVE_WATCHDOG=y
CONFIG_RAVE_SP_WATCHDOG=y
CONFIG_MLX_WDT=y
CONFIG_CADENCE_WATCHDOG=y
CONFIG_DW_WATCHDOG=y
CONFIG_RN5T618_WATCHDOG=y
CONFIG_TWL4030_WATCHDOG=y
CONFIG_MAX63XX_WATCHDOG=y
CONFIG_MAX77620_WATCHDOG=y
CONFIG_RETU_WATCHDOG=y
CONFIG_STPMIC1_WATCHDOG=y
CONFIG_ACQUIRE_WDT=y
CONFIG_ADVANTECH_WDT=y
CONFIG_ALIM1535_WDT=y
CONFIG_ALIM7101_WDT=y
CONFIG_EBC_C384_WDT=y
CONFIG_F71808E_WDT=y
CONFIG_SP5100_TCO=y
CONFIG_SBC_FITPC2_WATCHDOG=y
CONFIG_EUROTECH_WDT=y
CONFIG_IB700_WDT=y
CONFIG_IBMASR=y
CONFIG_WAFER_WDT=y
CONFIG_I6300ESB_WDT=y
CONFIG_IE6XX_WDT=y
CONFIG_INTEL_MID_WATCHDOG=y
CONFIG_ITCO_WDT=y
CONFIG_ITCO_VENDOR_SUPPORT=y
CONFIG_IT8712F_WDT=y
CONFIG_IT87_WDT=y
CONFIG_HP_WATCHDOG=y
CONFIG_HPWDT_NMI_DECODING=y
CONFIG_KEMPLD_WDT=y
CONFIG_SC1200_WDT=y
CONFIG_PC87413_WDT=y
CONFIG_NV_TCO=y
CONFIG_60XX_WDT=y
CONFIG_CPU5_WDT=y
CONFIG_SMSC_SCH311X_WDT=y
CONFIG_SMSC37B787_WDT=y
CONFIG_TQMX86_WDT=y
CONFIG_VIA_WDT=y
CONFIG_W83627HF_WDT=y
CONFIG_W83877F_WDT=y
CONFIG_W83977F_WDT=y
CONFIG_MACHZ_WDT=y
CONFIG_SBC_EPX_C3_WATCHDOG=y
CONFIG_INTEL_MEI_WDT=y
CONFIG_NI903X_WDT=y
CONFIG_NIC7018_WDT=y
CONFIG_SIEMENS_SIMATIC_IPC_WDT=y
CONFIG_MEN_A21_WDT=y
CONFIG_XEN_WDT=y

#
# PCI-based Watchdog Cards
#
CONFIG_PCIPCWATCHDOG=y
CONFIG_WDTPCI=y

#
# USB-based Watchdog Cards
#
CONFIG_USBPCWATCHDOG=y
CONFIG_SSB_POSSIBLE=y
CONFIG_SSB=y
CONFIG_SSB_SPROM=y
CONFIG_SSB_BLOCKIO=y
CONFIG_SSB_PCIHOST_POSSIBLE=y
CONFIG_SSB_PCIHOST=y
CONFIG_SSB_B43_PCI_BRIDGE=y
CONFIG_SSB_PCMCIAHOST_POSSIBLE=y
CONFIG_SSB_PCMCIAHOST=y
CONFIG_SSB_SDIOHOST_POSSIBLE=y
CONFIG_SSB_SDIOHOST=y
CONFIG_SSB_DRIVER_PCICORE_POSSIBLE=y
CONFIG_SSB_DRIVER_PCICORE=y
CONFIG_SSB_DRIVER_GPIO=y
CONFIG_BCMA_POSSIBLE=y
CONFIG_BCMA=y
CONFIG_BCMA_BLOCKIO=y
CONFIG_BCMA_HOST_PCI_POSSIBLE=y
CONFIG_BCMA_HOST_PCI=y
CONFIG_BCMA_HOST_SOC=y
CONFIG_BCMA_DRIVER_PCI=y
CONFIG_BCMA_SFLASH=y
CONFIG_BCMA_DRIVER_GMAC_CMN=y
CONFIG_BCMA_DRIVER_GPIO=y
CONFIG_BCMA_DEBUG=y

#
# Multifunction device drivers
#
CONFIG_MFD_CORE=y
CONFIG_MFD_ACT8945A=y
CONFIG_MFD_AS3711=y
CONFIG_MFD_AS3722=y
CONFIG_PMIC_ADP5520=y
CONFIG_MFD_AAT2870_CORE=y
CONFIG_MFD_ATMEL_FLEXCOM=y
CONFIG_MFD_ATMEL_HLCDC=y
CONFIG_MFD_BCM590XX=y
CONFIG_MFD_BD9571MWV=y
CONFIG_MFD_AXP20X=y
CONFIG_MFD_AXP20X_I2C=y
CONFIG_MFD_CROS_EC_DEV=y
CONFIG_MFD_MADERA=y
CONFIG_MFD_MADERA_I2C=y
CONFIG_MFD_MADERA_SPI=y
CONFIG_MFD_CS47L15=y
CONFIG_MFD_CS47L35=y
CONFIG_MFD_CS47L85=y
CONFIG_MFD_CS47L90=y
CONFIG_MFD_CS47L92=y
CONFIG_PMIC_DA903X=y
CONFIG_PMIC_DA9052=y
CONFIG_MFD_DA9052_SPI=y
CONFIG_MFD_DA9052_I2C=y
CONFIG_MFD_DA9055=y
CONFIG_MFD_DA9062=y
CONFIG_MFD_DA9063=y
CONFIG_MFD_DA9150=y
CONFIG_MFD_DLN2=y
CONFIG_MFD_GATEWORKS_GSC=y
CONFIG_MFD_MC13XXX=y
CONFIG_MFD_MC13XXX_SPI=y
CONFIG_MFD_MC13XXX_I2C=y
CONFIG_MFD_MP2629=y
CONFIG_MFD_HI6421_PMIC=y
CONFIG_MFD_HI6421_SPMI=y
CONFIG_HTC_PASIC3=y
CONFIG_HTC_I2CPLD=y
CONFIG_MFD_INTEL_QUARK_I2C_GPIO=y
CONFIG_LPC_ICH=y
CONFIG_LPC_SCH=y
CONFIG_INTEL_SOC_PMIC=y
CONFIG_INTEL_SOC_PMIC_BXTWC=y
CONFIG_INTEL_SOC_PMIC_CHTWC=y
CONFIG_INTEL_SOC_PMIC_CHTDC_TI=y
CONFIG_INTEL_SOC_PMIC_MRFLD=y
CONFIG_MFD_INTEL_LPSS=y
CONFIG_MFD_INTEL_LPSS_ACPI=y
CONFIG_MFD_INTEL_LPSS_PCI=y
CONFIG_MFD_INTEL_PMC_BXT=y
CONFIG_MFD_IQS62X=y
CONFIG_MFD_JANZ_CMODIO=y
CONFIG_MFD_KEMPLD=y
CONFIG_MFD_88PM800=y
CONFIG_MFD_88PM805=y
CONFIG_MFD_88PM860X=y
CONFIG_MFD_MAX14577=y
CONFIG_MFD_MAX77620=y
CONFIG_MFD_MAX77650=y
CONFIG_MFD_MAX77686=y
CONFIG_MFD_MAX77693=y
CONFIG_MFD_MAX77714=y
CONFIG_MFD_MAX77843=y
CONFIG_MFD_MAX8907=y
CONFIG_MFD_MAX8925=y
CONFIG_MFD_MAX8997=y
CONFIG_MFD_MAX8998=y
CONFIG_MFD_MT6360=y
CONFIG_MFD_MT6397=y
CONFIG_MFD_MENF21BMC=y
CONFIG_EZX_PCAP=y
CONFIG_MFD_CPCAP=y
CONFIG_MFD_VIPERBOARD=y
CONFIG_MFD_NTXEC=y
CONFIG_MFD_RETU=y
CONFIG_MFD_PCF50633=y
CONFIG_PCF50633_ADC=y
CONFIG_PCF50633_GPIO=y
CONFIG_UCB1400_CORE=y
CONFIG_MFD_RDC321X=y
CONFIG_MFD_RT4831=y
CONFIG_MFD_RT5033=y
CONFIG_MFD_RC5T583=y
CONFIG_MFD_RK808=y
CONFIG_MFD_RN5T618=y
CONFIG_MFD_SEC_CORE=y
CONFIG_MFD_SI476X_CORE=y
CONFIG_MFD_SIMPLE_MFD_I2C=y
CONFIG_MFD_SM501=y
CONFIG_MFD_SM501_GPIO=y
CONFIG_MFD_SKY81452=y
CONFIG_MFD_STMPE=y

#
# STMicroelectronics STMPE Interface Drivers
#
CONFIG_STMPE_I2C=y
CONFIG_STMPE_SPI=y
# end of STMicroelectronics STMPE Interface Drivers

CONFIG_MFD_SYSCON=y
CONFIG_MFD_TI_AM335X_TSCADC=y
CONFIG_MFD_LP3943=y
CONFIG_MFD_LP8788=y
CONFIG_MFD_TI_LMU=y
CONFIG_MFD_PALMAS=y
CONFIG_TPS6105X=y
CONFIG_TPS65010=y
CONFIG_TPS6507X=y
CONFIG_MFD_TPS65086=y
CONFIG_MFD_TPS65090=y
CONFIG_MFD_TPS65217=y
CONFIG_MFD_TI_LP873X=y
CONFIG_MFD_TI_LP87565=y
CONFIG_MFD_TPS65218=y
CONFIG_MFD_TPS6586X=y
CONFIG_MFD_TPS65910=y
CONFIG_MFD_TPS65912=y
CONFIG_MFD_TPS65912_I2C=y
CONFIG_MFD_TPS65912_SPI=y
CONFIG_TWL4030_CORE=y
CONFIG_MFD_TWL4030_AUDIO=y
CONFIG_TWL6040_CORE=y
CONFIG_MFD_WL1273_CORE=y
CONFIG_MFD_LM3533=y
CONFIG_MFD_TC3589X=y
CONFIG_MFD_TQMX86=y
CONFIG_MFD_VX855=y
CONFIG_MFD_LOCHNAGAR=y
CONFIG_MFD_ARIZONA=y
CONFIG_MFD_ARIZONA_I2C=y
CONFIG_MFD_ARIZONA_SPI=y
CONFIG_MFD_CS47L24=y
CONFIG_MFD_WM5102=y
CONFIG_MFD_WM5110=y
CONFIG_MFD_WM8997=y
CONFIG_MFD_WM8998=y
CONFIG_MFD_WM8400=y
CONFIG_MFD_WM831X=y
CONFIG_MFD_WM831X_I2C=y
CONFIG_MFD_WM831X_SPI=y
CONFIG_MFD_WM8350=y
CONFIG_MFD_WM8350_I2C=y
CONFIG_MFD_WM8994=y
CONFIG_MFD_ROHM_BD718XX=y
CONFIG_MFD_ROHM_BD71828=y
CONFIG_MFD_ROHM_BD957XMUF=y
CONFIG_MFD_STPMIC1=y
CONFIG_MFD_STMFX=y
CONFIG_MFD_WCD934X=y
CONFIG_MFD_ATC260X=y
CONFIG_MFD_ATC260X_I2C=y
CONFIG_MFD_QCOM_PM8008=y
CONFIG_RAVE_SP_CORE=y
CONFIG_MFD_INTEL_M10_BMC=y
CONFIG_MFD_RSMU_I2C=y
CONFIG_MFD_RSMU_SPI=y
# end of Multifunction device drivers

CONFIG_REGULATOR=y
CONFIG_REGULATOR_DEBUG=y
CONFIG_REGULATOR_FIXED_VOLTAGE=y
CONFIG_REGULATOR_VIRTUAL_CONSUMER=y
CONFIG_REGULATOR_USERSPACE_CONSUMER=y
CONFIG_REGULATOR_88PG86X=y
CONFIG_REGULATOR_88PM800=y
CONFIG_REGULATOR_88PM8607=y
CONFIG_REGULATOR_ACT8865=y
CONFIG_REGULATOR_ACT8945A=y
CONFIG_REGULATOR_AD5398=y
CONFIG_REGULATOR_AAT2870=y
CONFIG_REGULATOR_ARIZONA_LDO1=y
CONFIG_REGULATOR_ARIZONA_MICSUPP=y
CONFIG_REGULATOR_AS3711=y
CONFIG_REGULATOR_AS3722=y
CONFIG_REGULATOR_ATC260X=y
CONFIG_REGULATOR_AXP20X=y
CONFIG_REGULATOR_BCM590XX=y
CONFIG_REGULATOR_BD71815=y
CONFIG_REGULATOR_BD71828=y
CONFIG_REGULATOR_BD718XX=y
CONFIG_REGULATOR_BD9571MWV=y
CONFIG_REGULATOR_BD957XMUF=y
CONFIG_REGULATOR_CPCAP=y
CONFIG_REGULATOR_CROS_EC=y
CONFIG_REGULATOR_DA903X=y
CONFIG_REGULATOR_DA9052=y
CONFIG_REGULATOR_DA9055=y
CONFIG_REGULATOR_DA9062=y
CONFIG_REGULATOR_DA9063=y
CONFIG_REGULATOR_DA9121=y
CONFIG_REGULATOR_DA9210=y
CONFIG_REGULATOR_DA9211=y
CONFIG_REGULATOR_FAN53555=y
CONFIG_REGULATOR_FAN53880=y
CONFIG_REGULATOR_GPIO=y
CONFIG_REGULATOR_HI6421=y
CONFIG_REGULATOR_HI6421V530=y
CONFIG_REGULATOR_HI6421V600=y
CONFIG_REGULATOR_ISL9305=y
CONFIG_REGULATOR_ISL6271A=y
CONFIG_REGULATOR_LM363X=y
CONFIG_REGULATOR_LOCHNAGAR=y
CONFIG_REGULATOR_LP3971=y
CONFIG_REGULATOR_LP3972=y
CONFIG_REGULATOR_LP872X=y
CONFIG_REGULATOR_LP873X=y
CONFIG_REGULATOR_LP8755=y
CONFIG_REGULATOR_LP87565=y
CONFIG_REGULATOR_LP8788=y
CONFIG_REGULATOR_LTC3589=y
CONFIG_REGULATOR_LTC3676=y
CONFIG_REGULATOR_MAX14577=y
CONFIG_REGULATOR_MAX1586=y
CONFIG_REGULATOR_MAX77620=y
CONFIG_REGULATOR_MAX77650=y
CONFIG_REGULATOR_MAX8649=y
CONFIG_REGULATOR_MAX8660=y
CONFIG_REGULATOR_MAX8893=y
CONFIG_REGULATOR_MAX8907=y
CONFIG_REGULATOR_MAX8925=y
CONFIG_REGULATOR_MAX8952=y
CONFIG_REGULATOR_MAX8973=y
CONFIG_REGULATOR_MAX8997=y
CONFIG_REGULATOR_MAX8998=y
CONFIG_REGULATOR_MAX20086=y
CONFIG_REGULATOR_MAX77686=y
CONFIG_REGULATOR_MAX77693=y
CONFIG_REGULATOR_MAX77802=y
CONFIG_REGULATOR_MAX77826=y
CONFIG_REGULATOR_MC13XXX_CORE=y
CONFIG_REGULATOR_MC13783=y
CONFIG_REGULATOR_MC13892=y
CONFIG_REGULATOR_MCP16502=y
CONFIG_REGULATOR_MP5416=y
CONFIG_REGULATOR_MP8859=y
CONFIG_REGULATOR_MP886X=y
CONFIG_REGULATOR_MPQ7920=y
CONFIG_REGULATOR_MT6311=y
CONFIG_REGULATOR_MT6315=y
CONFIG_REGULATOR_MT6323=y
CONFIG_REGULATOR_MT6358=y
CONFIG_REGULATOR_MT6359=y
CONFIG_REGULATOR_MT6360=y
CONFIG_REGULATOR_MT6397=y
CONFIG_REGULATOR_PALMAS=y
CONFIG_REGULATOR_PCA9450=y
CONFIG_REGULATOR_PCAP=y
CONFIG_REGULATOR_PCF50633=y
CONFIG_REGULATOR_PF8X00=y
CONFIG_REGULATOR_PFUZE100=y
CONFIG_REGULATOR_PV88060=y
CONFIG_REGULATOR_PV88080=y
CONFIG_REGULATOR_PV88090=y
CONFIG_REGULATOR_PWM=y
CONFIG_REGULATOR_QCOM_SPMI=y
CONFIG_REGULATOR_QCOM_USB_VBUS=y
CONFIG_REGULATOR_RASPBERRYPI_TOUCHSCREEN_ATTINY=y
CONFIG_REGULATOR_RC5T583=y
CONFIG_REGULATOR_RK808=y
CONFIG_REGULATOR_RN5T618=y
CONFIG_REGULATOR_ROHM=y
CONFIG_REGULATOR_RT4801=y
CONFIG_REGULATOR_RT4831=y
CONFIG_REGULATOR_RT5033=y
CONFIG_REGULATOR_RT5190A=y
CONFIG_REGULATOR_RT5759=y
CONFIG_REGULATOR_RT6160=y
CONFIG_REGULATOR_RT6245=y
CONFIG_REGULATOR_RTQ2134=y
CONFIG_REGULATOR_RTMV20=y
CONFIG_REGULATOR_RTQ6752=y
CONFIG_REGULATOR_S2MPA01=y
CONFIG_REGULATOR_S2MPS11=y
CONFIG_REGULATOR_S5M8767=y
CONFIG_REGULATOR_SKY81452=y
CONFIG_REGULATOR_SLG51000=y
CONFIG_REGULATOR_STPMIC1=y
CONFIG_REGULATOR_SY7636A=y
CONFIG_REGULATOR_SY8106A=y
CONFIG_REGULATOR_SY8824X=y
CONFIG_REGULATOR_SY8827N=y
CONFIG_REGULATOR_TPS51632=y
CONFIG_REGULATOR_TPS6105X=y
CONFIG_REGULATOR_TPS62360=y
CONFIG_REGULATOR_TPS6286X=y
CONFIG_REGULATOR_TPS65023=y
CONFIG_REGULATOR_TPS6507X=y
CONFIG_REGULATOR_TPS65086=y
CONFIG_REGULATOR_TPS65090=y
CONFIG_REGULATOR_TPS65132=y
CONFIG_REGULATOR_TPS65217=y
CONFIG_REGULATOR_TPS65218=y
CONFIG_REGULATOR_TPS6524X=y
CONFIG_REGULATOR_TPS6586X=y
CONFIG_REGULATOR_TPS65910=y
CONFIG_REGULATOR_TPS65912=y
CONFIG_REGULATOR_TPS68470=y
CONFIG_REGULATOR_TWL4030=y
CONFIG_REGULATOR_VCTRL=y
CONFIG_REGULATOR_WM831X=y
CONFIG_REGULATOR_WM8350=y
CONFIG_REGULATOR_WM8400=y
CONFIG_REGULATOR_WM8994=y
CONFIG_REGULATOR_QCOM_LABIBB=y
CONFIG_RC_CORE=y
CONFIG_BPF_LIRC_MODE2=y
CONFIG_LIRC=y
CONFIG_RC_MAP=y
CONFIG_RC_DECODERS=y
CONFIG_IR_IMON_DECODER=y
CONFIG_IR_JVC_DECODER=y
CONFIG_IR_MCE_KBD_DECODER=y
CONFIG_IR_NEC_DECODER=y
CONFIG_IR_RC5_DECODER=y
CONFIG_IR_RC6_DECODER=y
CONFIG_IR_RCMM_DECODER=y
CONFIG_IR_SANYO_DECODER=y
CONFIG_IR_SHARP_DECODER=y
CONFIG_IR_SONY_DECODER=y
CONFIG_IR_XMP_DECODER=y
CONFIG_RC_DEVICES=y
CONFIG_IR_ENE=y
CONFIG_IR_FINTEK=y
CONFIG_IR_GPIO_CIR=y
CONFIG_IR_GPIO_TX=y
CONFIG_IR_HIX5HD2=y
CONFIG_IR_IGORPLUGUSB=y
CONFIG_IR_IGUANA=y
CONFIG_IR_IMON=y
CONFIG_IR_IMON_RAW=y
CONFIG_IR_ITE_CIR=y
CONFIG_IR_MCEUSB=y
CONFIG_IR_NUVOTON=y
CONFIG_IR_PWM_TX=y
CONFIG_IR_REDRAT3=y
CONFIG_IR_SERIAL=y
CONFIG_IR_SERIAL_TRANSMITTER=y
CONFIG_IR_SPI=y
CONFIG_IR_STREAMZAP=y
CONFIG_IR_TOY=y
CONFIG_IR_TTUSBIR=y
CONFIG_IR_WINBOND_CIR=y
CONFIG_RC_ATI_REMOTE=y
CONFIG_RC_LOOPBACK=y
CONFIG_RC_XBOX_DVD=y
CONFIG_CEC_CORE=y
CONFIG_CEC_NOTIFIER=y
CONFIG_CEC_PIN=y

#
# CEC support
#
CONFIG_MEDIA_CEC_RC=y
CONFIG_CEC_PIN_ERROR_INJ=y
CONFIG_MEDIA_CEC_SUPPORT=y
CONFIG_CEC_CH7322=y
CONFIG_CEC_CROS_EC=y
CONFIG_CEC_GPIO=y
CONFIG_CEC_SECO=y
CONFIG_CEC_SECO_RC=y
CONFIG_USB_PULSE8_CEC=y
CONFIG_USB_RAINSHADOW_CEC=y
# end of CEC support

CONFIG_MEDIA_SUPPORT=y
CONFIG_MEDIA_SUPPORT_FILTER=y
CONFIG_MEDIA_SUBDRV_AUTOSELECT=y

#
# Media device types
#
CONFIG_MEDIA_CAMERA_SUPPORT=y
CONFIG_MEDIA_ANALOG_TV_SUPPORT=y
CONFIG_MEDIA_DIGITAL_TV_SUPPORT=y
CONFIG_MEDIA_RADIO_SUPPORT=y
CONFIG_MEDIA_SDR_SUPPORT=y
CONFIG_MEDIA_PLATFORM_SUPPORT=y
CONFIG_MEDIA_TEST_SUPPORT=y
# end of Media device types

CONFIG_VIDEO_DEV=y
CONFIG_MEDIA_CONTROLLER=y
CONFIG_DVB_CORE=y

#
# Video4Linux options
#
CONFIG_VIDEO_V4L2_I2C=y
CONFIG_VIDEO_V4L2_SUBDEV_API=y
CONFIG_VIDEO_ADV_DEBUG=y
CONFIG_VIDEO_FIXED_MINOR_RANGES=y
CONFIG_VIDEO_TUNER=y
CONFIG_V4L2_MEM2MEM_DEV=y
CONFIG_V4L2_FLASH_LED_CLASS=y
CONFIG_V4L2_FWNODE=y
CONFIG_V4L2_ASYNC=y
CONFIG_VIDEOBUF_GEN=y
CONFIG_VIDEOBUF_DMA_SG=y
CONFIG_VIDEOBUF_VMALLOC=y
# end of Video4Linux options

#
# Media controller options
#
CONFIG_MEDIA_CONTROLLER_DVB=y
CONFIG_MEDIA_CONTROLLER_REQUEST_API=y
# end of Media controller options

#
# Digital TV options
#
CONFIG_DVB_MMAP=y
CONFIG_DVB_NET=y
CONFIG_DVB_MAX_ADAPTERS=16
CONFIG_DVB_DYNAMIC_MINORS=y
CONFIG_DVB_DEMUX_SECTION_LOSS_LOG=y
CONFIG_DVB_ULE_DEBUG=y
# end of Digital TV options

#
# Media drivers
#

#
# Drivers filtered as selected at 'Filter media drivers'
#

#
# Media drivers
#
CONFIG_MEDIA_USB_SUPPORT=y

#
# Webcam devices
#
CONFIG_VIDEO_CPIA2=y
CONFIG_USB_GSPCA=y
CONFIG_USB_GSPCA_BENQ=y
CONFIG_USB_GSPCA_CONEX=y
CONFIG_USB_GSPCA_CPIA1=y
CONFIG_USB_GSPCA_DTCS033=y
CONFIG_USB_GSPCA_ETOMS=y
CONFIG_USB_GSPCA_FINEPIX=y
CONFIG_USB_GSPCA_JEILINJ=y
CONFIG_USB_GSPCA_JL2005BCD=y
CONFIG_USB_GSPCA_KINECT=y
CONFIG_USB_GSPCA_KONICA=y
CONFIG_USB_GSPCA_MARS=y
CONFIG_USB_GSPCA_MR97310A=y
CONFIG_USB_GSPCA_NW80X=y
CONFIG_USB_GSPCA_OV519=y
CONFIG_USB_GSPCA_OV534=y
CONFIG_USB_GSPCA_OV534_9=y
CONFIG_USB_GSPCA_PAC207=y
CONFIG_USB_GSPCA_PAC7302=y
CONFIG_USB_GSPCA_PAC7311=y
CONFIG_USB_GSPCA_SE401=y
CONFIG_USB_GSPCA_SN9C2028=y
CONFIG_USB_GSPCA_SN9C20X=y
CONFIG_USB_GSPCA_SONIXB=y
CONFIG_USB_GSPCA_SONIXJ=y
CONFIG_USB_GSPCA_SPCA1528=y
CONFIG_USB_GSPCA_SPCA500=y
CONFIG_USB_GSPCA_SPCA501=y
CONFIG_USB_GSPCA_SPCA505=y
CONFIG_USB_GSPCA_SPCA506=y
CONFIG_USB_GSPCA_SPCA508=y
CONFIG_USB_GSPCA_SPCA561=y
CONFIG_USB_GSPCA_SQ905=y
CONFIG_USB_GSPCA_SQ905C=y
CONFIG_USB_GSPCA_SQ930X=y
CONFIG_USB_GSPCA_STK014=y
CONFIG_USB_GSPCA_STK1135=y
CONFIG_USB_GSPCA_STV0680=y
CONFIG_USB_GSPCA_SUNPLUS=y
CONFIG_USB_GSPCA_T613=y
CONFIG_USB_GSPCA_TOPRO=y
CONFIG_USB_GSPCA_TOUPTEK=y
CONFIG_USB_GSPCA_TV8532=y
CONFIG_USB_GSPCA_VC032X=y
CONFIG_USB_GSPCA_VICAM=y
CONFIG_USB_GSPCA_XIRLINK_CIT=y
CONFIG_USB_GSPCA_ZC3XX=y
CONFIG_USB_GL860=y
CONFIG_USB_M5602=y
CONFIG_USB_STV06XX=y
CONFIG_USB_PWC=y
CONFIG_USB_PWC_DEBUG=y
CONFIG_USB_PWC_INPUT_EVDEV=y
CONFIG_USB_S2255=y
CONFIG_VIDEO_USBTV=y
CONFIG_USB_VIDEO_CLASS=y
CONFIG_USB_VIDEO_CLASS_INPUT_EVDEV=y
CONFIG_USB_ZR364XX=y

#
# Analog TV USB devices
#
CONFIG_VIDEO_GO7007=y
CONFIG_VIDEO_GO7007_USB=y
CONFIG_VIDEO_GO7007_LOADER=y
CONFIG_VIDEO_GO7007_USB_S2250_BOARD=y
CONFIG_VIDEO_HDPVR=y
CONFIG_VIDEO_PVRUSB2=y
CONFIG_VIDEO_PVRUSB2_SYSFS=y
CONFIG_VIDEO_PVRUSB2_DVB=y
CONFIG_VIDEO_PVRUSB2_DEBUGIFC=y
CONFIG_VIDEO_STK1160_COMMON=y
CONFIG_VIDEO_STK1160=y

#
# Analog/digital TV USB devices
#
CONFIG_VIDEO_AU0828=y
CONFIG_VIDEO_AU0828_V4L2=y
CONFIG_VIDEO_AU0828_RC=y
CONFIG_VIDEO_CX231XX=y
CONFIG_VIDEO_CX231XX_RC=y
CONFIG_VIDEO_CX231XX_ALSA=y
CONFIG_VIDEO_CX231XX_DVB=y
CONFIG_VIDEO_TM6000=y
CONFIG_VIDEO_TM6000_ALSA=y
CONFIG_VIDEO_TM6000_DVB=y

#
# Digital TV USB devices
#
CONFIG_DVB_AS102=y
CONFIG_DVB_B2C2_FLEXCOP_USB=y
CONFIG_DVB_B2C2_FLEXCOP_USB_DEBUG=y
CONFIG_DVB_USB_V2=y
CONFIG_DVB_USB_AF9015=y
CONFIG_DVB_USB_AF9035=y
CONFIG_DVB_USB_ANYSEE=y
CONFIG_DVB_USB_AU6610=y
CONFIG_DVB_USB_AZ6007=y
CONFIG_DVB_USB_CE6230=y
CONFIG_DVB_USB_DVBSKY=y
CONFIG_DVB_USB_EC168=y
CONFIG_DVB_USB_GL861=y
CONFIG_DVB_USB_LME2510=y
CONFIG_DVB_USB_MXL111SF=y
CONFIG_DVB_USB_RTL28XXU=y
CONFIG_DVB_USB_ZD1301=y
CONFIG_DVB_USB=y
CONFIG_DVB_USB_DEBUG=y
CONFIG_DVB_USB_A800=y
CONFIG_DVB_USB_AF9005=y
CONFIG_DVB_USB_AF9005_REMOTE=y
CONFIG_DVB_USB_AZ6027=y
CONFIG_DVB_USB_CINERGY_T2=y
CONFIG_DVB_USB_CXUSB=y
CONFIG_DVB_USB_CXUSB_ANALOG=y
CONFIG_DVB_USB_DIB0700=y
CONFIG_DVB_USB_DIB3000MC=y
CONFIG_DVB_USB_DIBUSB_MB=y
CONFIG_DVB_USB_DIBUSB_MB_FAULTY=y
CONFIG_DVB_USB_DIBUSB_MC=y
CONFIG_DVB_USB_DIGITV=y
CONFIG_DVB_USB_DTT200U=y
CONFIG_DVB_USB_DTV5100=y
CONFIG_DVB_USB_DW2102=y
CONFIG_DVB_USB_GP8PSK=y
CONFIG_DVB_USB_M920X=y
CONFIG_DVB_USB_NOVA_T_USB2=y
CONFIG_DVB_USB_OPERA1=y
CONFIG_DVB_USB_PCTV452E=y
CONFIG_DVB_USB_TECHNISAT_USB2=y
CONFIG_DVB_USB_TTUSB2=y
CONFIG_DVB_USB_UMT_010=y
CONFIG_DVB_USB_VP702X=y
CONFIG_DVB_USB_VP7045=y
CONFIG_SMS_USB_DRV=y
CONFIG_DVB_TTUSB_BUDGET=y
CONFIG_DVB_TTUSB_DEC=y

#
# Webcam, TV (analog/digital) USB devices
#
CONFIG_VIDEO_EM28XX=y
CONFIG_VIDEO_EM28XX_V4L2=y
CONFIG_VIDEO_EM28XX_ALSA=y
CONFIG_VIDEO_EM28XX_DVB=y
CONFIG_VIDEO_EM28XX_RC=y

#
# Software defined radio USB devices
#
CONFIG_USB_AIRSPY=y
CONFIG_USB_HACKRF=y
CONFIG_USB_MSI2500=y
CONFIG_MEDIA_PCI_SUPPORT=y

#
# Media capture support
#
CONFIG_VIDEO_MEYE=y
CONFIG_VIDEO_SOLO6X10=y
CONFIG_VIDEO_TW5864=y
CONFIG_VIDEO_TW68=y
CONFIG_VIDEO_TW686X=y

#
# Media capture/analog TV support
#
CONFIG_VIDEO_DT3155=y
CONFIG_VIDEO_IVTV=y
CONFIG_VIDEO_IVTV_ALSA=y
CONFIG_VIDEO_FB_IVTV=y
CONFIG_VIDEO_FB_IVTV_FORCE_PAT=y
CONFIG_VIDEO_HEXIUM_GEMINI=y
CONFIG_VIDEO_HEXIUM_ORION=y
CONFIG_VIDEO_MXB=y

#
# Media capture/analog/hybrid TV support
#
CONFIG_VIDEO_BT848=y
CONFIG_DVB_BT8XX=y
CONFIG_VIDEO_CX18=y
CONFIG_VIDEO_CX18_ALSA=y
CONFIG_VIDEO_CX23885=y
CONFIG_MEDIA_ALTERA_CI=y
CONFIG_VIDEO_CX25821=y
CONFIG_VIDEO_CX25821_ALSA=y
CONFIG_VIDEO_CX88=y
CONFIG_VIDEO_CX88_ALSA=y
CONFIG_VIDEO_CX88_BLACKBIRD=y
CONFIG_VIDEO_CX88_DVB=y
CONFIG_VIDEO_CX88_ENABLE_VP3054=y
CONFIG_VIDEO_CX88_VP3054=y
CONFIG_VIDEO_CX88_MPEG=y
CONFIG_VIDEO_SAA7134=y
CONFIG_VIDEO_SAA7134_ALSA=y
CONFIG_VIDEO_SAA7134_RC=y
CONFIG_VIDEO_SAA7134_DVB=y
CONFIG_VIDEO_SAA7134_GO7007=y
CONFIG_VIDEO_SAA7164=y

#
# Media digital TV PCI Adapters
#
CONFIG_DVB_B2C2_FLEXCOP_PCI=y
CONFIG_DVB_B2C2_FLEXCOP_PCI_DEBUG=y
CONFIG_DVB_DDBRIDGE=y
CONFIG_DVB_DDBRIDGE_MSIENABLE=y
CONFIG_DVB_DM1105=y
CONFIG_MANTIS_CORE=y
CONFIG_DVB_MANTIS=y
CONFIG_DVB_HOPPER=y
CONFIG_DVB_NETUP_UNIDVB=y
CONFIG_DVB_NGENE=y
CONFIG_DVB_PLUTO2=y
CONFIG_DVB_PT1=y
CONFIG_DVB_PT3=y
CONFIG_DVB_SMIPCIE=y
CONFIG_DVB_BUDGET_CORE=y
CONFIG_DVB_BUDGET=y
CONFIG_DVB_BUDGET_CI=y
CONFIG_DVB_BUDGET_AV=y
CONFIG_VIDEO_PCI_SKELETON=y
CONFIG_VIDEO_IPU3_CIO2=y
CONFIG_CIO2_BRIDGE=y
CONFIG_RADIO_ADAPTERS=y
CONFIG_RADIO_MAXIRADIO=y
CONFIG_RADIO_SAA7706H=y
CONFIG_RADIO_SHARK=y
CONFIG_RADIO_SHARK2=y
CONFIG_RADIO_SI4713=y
CONFIG_RADIO_SI476X=y
CONFIG_RADIO_TEA575X=y
CONFIG_RADIO_TEA5764=y
CONFIG_RADIO_TEA5764_XTAL=y
CONFIG_RADIO_TEF6862=y
CONFIG_RADIO_WL1273=y
CONFIG_USB_DSBR=y
CONFIG_USB_KEENE=y
CONFIG_USB_MA901=y
CONFIG_USB_MR800=y
CONFIG_USB_RAREMONO=y
CONFIG_RADIO_SI470X=y
CONFIG_USB_SI470X=y
CONFIG_I2C_SI470X=y
CONFIG_USB_SI4713=y
CONFIG_PLATFORM_SI4713=y
CONFIG_I2C_SI4713=y
CONFIG_RADIO_WL128X=y
CONFIG_MEDIA_PLATFORM_DRIVERS=y
CONFIG_V4L_PLATFORM_DRIVERS=y
CONFIG_SDR_PLATFORM_DRIVERS=y
CONFIG_DVB_PLATFORM_DRIVERS=y
CONFIG_V4L_MEM2MEM_DRIVERS=y
CONFIG_VIDEO_MEM2MEM_DEINTERLACE=y
CONFIG_VIDEO_MUX=y

#
# Allegro DVT media platform drivers
#

#
# Amlogic media platform drivers
#

#
# Amphion drivers
#

#
# Aspeed media platform drivers
#
CONFIG_VIDEO_ASPEED=y

#
# Atmel media platform drivers
#

#
# Cadence media platform drivers
#
CONFIG_VIDEO_CADENCE_CSI2RX=y
CONFIG_VIDEO_CADENCE_CSI2TX=y

#
# Chips&Media media platform drivers
#

#
# Intel media platform drivers
#

#
# Marvell media platform drivers
#
CONFIG_VIDEO_CAFE_CCIC=y

#
# Mediatek media platform drivers
#

#
# NVidia media platform drivers
#

#
# NXP media platform drivers
#

#
# Qualcomm media platform drivers
#

#
# Renesas media platform drivers
#

#
# Rockchip media platform drivers
#

#
# Samsung media platform drivers
#

#
# STMicroelectronics media platform drivers
#

#
# Sunxi media platform drivers
#

#
# Texas Instruments drivers
#

#
# VIA media platform drivers
#
CONFIG_VIDEO_VIA_CAMERA=y

#
# Xilinx media platform drivers
#
CONFIG_VIDEO_XILINX=y
CONFIG_VIDEO_XILINX_CSI2RXSS=y
CONFIG_VIDEO_XILINX_TPG=y
CONFIG_VIDEO_XILINX_VTC=y

#
# MMC/SDIO DVB adapters
#
CONFIG_SMS_SDIO_DRV=y
CONFIG_V4L_TEST_DRIVERS=y
CONFIG_VIDEO_VIM2M=y
CONFIG_VIDEO_VICODEC=y
CONFIG_VIDEO_VIMC=y
CONFIG_VIDEO_VIVID=y
CONFIG_VIDEO_VIVID_CEC=y
CONFIG_VIDEO_VIVID_MAX_DEVS=64
CONFIG_DVB_TEST_DRIVERS=y
CONFIG_DVB_VIDTV=y

#
# FireWire (IEEE 1394) Adapters
#
CONFIG_DVB_FIREDTV=y
CONFIG_DVB_FIREDTV_INPUT=y
CONFIG_MEDIA_COMMON_OPTIONS=y

#
# common driver options
#
CONFIG_CYPRESS_FIRMWARE=y
CONFIG_TTPCI_EEPROM=y
CONFIG_VIDEO_CX2341X=y
CONFIG_VIDEO_TVEEPROM=y
CONFIG_DVB_B2C2_FLEXCOP=y
CONFIG_DVB_B2C2_FLEXCOP_DEBUG=y
CONFIG_VIDEO_SAA7146=y
CONFIG_VIDEO_SAA7146_VV=y
CONFIG_SMS_SIANO_MDTV=y
CONFIG_SMS_SIANO_RC=y
CONFIG_SMS_SIANO_DEBUGFS=y
CONFIG_VIDEO_V4L2_TPG=y
CONFIG_VIDEOBUF2_CORE=y
CONFIG_VIDEOBUF2_V4L2=y
CONFIG_VIDEOBUF2_MEMOPS=y
CONFIG_VIDEOBUF2_DMA_CONTIG=y
CONFIG_VIDEOBUF2_VMALLOC=y
CONFIG_VIDEOBUF2_DMA_SG=y
CONFIG_VIDEOBUF2_DVB=y
# end of Media drivers

#
# Media ancillary drivers
#
CONFIG_MEDIA_ATTACH=y

#
# IR I2C driver auto-selected by 'Autoselect ancillary drivers'
#
CONFIG_VIDEO_IR_I2C=y

#
# Camera sensor devices
#
CONFIG_VIDEO_APTINA_PLL=y
CONFIG_VIDEO_CCS_PLL=y
CONFIG_VIDEO_AR0521=y
CONFIG_VIDEO_HI556=y
CONFIG_VIDEO_HI846=y
CONFIG_VIDEO_HI847=y
CONFIG_VIDEO_IMX208=y
CONFIG_VIDEO_IMX214=y
CONFIG_VIDEO_IMX219=y
CONFIG_VIDEO_IMX258=y
CONFIG_VIDEO_IMX274=y
CONFIG_VIDEO_IMX290=y
CONFIG_VIDEO_IMX319=y
CONFIG_VIDEO_IMX334=y
CONFIG_VIDEO_IMX335=y
CONFIG_VIDEO_IMX355=y
CONFIG_VIDEO_IMX412=y
CONFIG_VIDEO_MAX9271_LIB=y
CONFIG_VIDEO_MT9M001=y
CONFIG_VIDEO_MT9M032=y
CONFIG_VIDEO_MT9M111=y
CONFIG_VIDEO_MT9P031=y
CONFIG_VIDEO_MT9T001=y
CONFIG_VIDEO_MT9T112=y
CONFIG_VIDEO_MT9V011=y
CONFIG_VIDEO_MT9V032=y
CONFIG_VIDEO_MT9V111=y
CONFIG_VIDEO_NOON010PC30=y
CONFIG_VIDEO_OG01A1B=y
CONFIG_VIDEO_OV02A10=y
CONFIG_VIDEO_OV08D10=y
CONFIG_VIDEO_OV13858=y
CONFIG_VIDEO_OV13B10=y
CONFIG_VIDEO_OV2640=y
CONFIG_VIDEO_OV2659=y
CONFIG_VIDEO_OV2680=y
CONFIG_VIDEO_OV2685=y
CONFIG_VIDEO_OV2740=y
CONFIG_VIDEO_OV5640=y
CONFIG_VIDEO_OV5645=y
CONFIG_VIDEO_OV5647=y
CONFIG_VIDEO_OV5648=y
CONFIG_VIDEO_OV5670=y
CONFIG_VIDEO_OV5675=y
CONFIG_VIDEO_OV5693=y
CONFIG_VIDEO_OV5695=y
CONFIG_VIDEO_OV6650=y
CONFIG_VIDEO_OV7251=y
CONFIG_VIDEO_OV7640=y
CONFIG_VIDEO_OV7670=y
CONFIG_VIDEO_OV772X=y
CONFIG_VIDEO_OV7740=y
CONFIG_VIDEO_OV8856=y
CONFIG_VIDEO_OV8865=y
CONFIG_VIDEO_OV9282=y
CONFIG_VIDEO_OV9640=y
CONFIG_VIDEO_OV9650=y
CONFIG_VIDEO_OV9734=y
CONFIG_VIDEO_RDACM20=y
CONFIG_VIDEO_RDACM21=y
CONFIG_VIDEO_RJ54N1=y
CONFIG_VIDEO_S5C73M3=y
CONFIG_VIDEO_S5K4ECGX=y
CONFIG_VIDEO_S5K5BAF=y
CONFIG_VIDEO_S5K6A3=y
CONFIG_VIDEO_S5K6AA=y
CONFIG_VIDEO_SR030PC30=y
CONFIG_VIDEO_VS6624=y
CONFIG_VIDEO_CCS=y
CONFIG_VIDEO_ET8EK8=y
CONFIG_VIDEO_M5MOLS=y
# end of Camera sensor devices

#
# Lens drivers
#
CONFIG_VIDEO_AD5820=y
CONFIG_VIDEO_AK7375=y
CONFIG_VIDEO_DW9714=y
CONFIG_VIDEO_DW9768=y
CONFIG_VIDEO_DW9807_VCM=y
# end of Lens drivers

#
# Flash devices
#
CONFIG_VIDEO_ADP1653=y
CONFIG_VIDEO_LM3560=y
CONFIG_VIDEO_LM3646=y
# end of Flash devices

#
# Audio decoders, processors and mixers
#
CONFIG_VIDEO_CS3308=y
CONFIG_VIDEO_CS5345=y
CONFIG_VIDEO_CS53L32A=y
CONFIG_VIDEO_MSP3400=y
CONFIG_VIDEO_SONY_BTF_MPX=y
CONFIG_VIDEO_TDA1997X=y
CONFIG_VIDEO_TDA7432=y
CONFIG_VIDEO_TDA9840=y
CONFIG_VIDEO_TEA6415C=y
CONFIG_VIDEO_TEA6420=y
CONFIG_VIDEO_TLV320AIC23B=y
CONFIG_VIDEO_TVAUDIO=y
CONFIG_VIDEO_UDA1342=y
CONFIG_VIDEO_VP27SMPX=y
CONFIG_VIDEO_WM8739=y
CONFIG_VIDEO_WM8775=y
# end of Audio decoders, processors and mixers

#
# RDS decoders
#
CONFIG_VIDEO_SAA6588=y
# end of RDS decoders

#
# Video decoders
#
CONFIG_VIDEO_ADV7180=y
CONFIG_VIDEO_ADV7183=y
CONFIG_VIDEO_ADV748X=y
CONFIG_VIDEO_ADV7604=y
CONFIG_VIDEO_ADV7604_CEC=y
CONFIG_VIDEO_ADV7842=y
CONFIG_VIDEO_ADV7842_CEC=y
CONFIG_VIDEO_BT819=y
CONFIG_VIDEO_BT856=y
CONFIG_VIDEO_BT866=y
CONFIG_VIDEO_ISL7998X=y
CONFIG_VIDEO_KS0127=y
CONFIG_VIDEO_MAX9286=y
CONFIG_VIDEO_ML86V7667=y
CONFIG_VIDEO_SAA7110=y
CONFIG_VIDEO_SAA711X=y
CONFIG_VIDEO_TC358743=y
CONFIG_VIDEO_TC358743_CEC=y
CONFIG_VIDEO_TVP514X=y
CONFIG_VIDEO_TVP5150=y
CONFIG_VIDEO_TVP7002=y
CONFIG_VIDEO_TW2804=y
CONFIG_VIDEO_TW9903=y
CONFIG_VIDEO_TW9906=y
CONFIG_VIDEO_TW9910=y
CONFIG_VIDEO_VPX3220=y

#
# Video and audio decoders
#
CONFIG_VIDEO_SAA717X=y
CONFIG_VIDEO_CX25840=y
# end of Video decoders

#
# Video encoders
#
CONFIG_VIDEO_AD9389B=y
CONFIG_VIDEO_ADV7170=y
CONFIG_VIDEO_ADV7175=y
CONFIG_VIDEO_ADV7343=y
CONFIG_VIDEO_ADV7393=y
CONFIG_VIDEO_AK881X=y
CONFIG_VIDEO_SAA7127=y
CONFIG_VIDEO_SAA7185=y
CONFIG_VIDEO_THS8200=y
# end of Video encoders

#
# Video improvement chips
#
CONFIG_VIDEO_UPD64031A=y
CONFIG_VIDEO_UPD64083=y
# end of Video improvement chips

#
# Audio/Video compression chips
#
CONFIG_VIDEO_SAA6752HS=y
# end of Audio/Video compression chips

#
# SDR tuner chips
#
CONFIG_SDR_MAX2175=y
# end of SDR tuner chips

#
# Miscellaneous helper chips
#
CONFIG_VIDEO_I2C=y
CONFIG_VIDEO_M52790=y
CONFIG_VIDEO_ST_MIPID02=y
CONFIG_VIDEO_THS7303=y
# end of Miscellaneous helper chips

#
# Media SPI Adapters
#
CONFIG_CXD2880_SPI_DRV=y
CONFIG_VIDEO_GS1662=y
# end of Media SPI Adapters

CONFIG_MEDIA_TUNER=y

#
# Customize TV tuners
#
CONFIG_MEDIA_TUNER_E4000=y
CONFIG_MEDIA_TUNER_FC0011=y
CONFIG_MEDIA_TUNER_FC0012=y
CONFIG_MEDIA_TUNER_FC0013=y
CONFIG_MEDIA_TUNER_FC2580=y
CONFIG_MEDIA_TUNER_IT913X=y
CONFIG_MEDIA_TUNER_M88RS6000T=y
CONFIG_MEDIA_TUNER_MAX2165=y
CONFIG_MEDIA_TUNER_MC44S803=y
CONFIG_MEDIA_TUNER_MSI001=y
CONFIG_MEDIA_TUNER_MT2060=y
CONFIG_MEDIA_TUNER_MT2063=y
CONFIG_MEDIA_TUNER_MT20XX=y
CONFIG_MEDIA_TUNER_MT2131=y
CONFIG_MEDIA_TUNER_MT2266=y
CONFIG_MEDIA_TUNER_MXL301RF=y
CONFIG_MEDIA_TUNER_MXL5005S=y
CONFIG_MEDIA_TUNER_MXL5007T=y
CONFIG_MEDIA_TUNER_QM1D1B0004=y
CONFIG_MEDIA_TUNER_QM1D1C0042=y
CONFIG_MEDIA_TUNER_QT1010=y
CONFIG_MEDIA_TUNER_R820T=y
CONFIG_MEDIA_TUNER_SI2157=y
CONFIG_MEDIA_TUNER_SIMPLE=y
CONFIG_MEDIA_TUNER_TDA18212=y
CONFIG_MEDIA_TUNER_TDA18218=y
CONFIG_MEDIA_TUNER_TDA18250=y
CONFIG_MEDIA_TUNER_TDA18271=y
CONFIG_MEDIA_TUNER_TDA827X=y
CONFIG_MEDIA_TUNER_TDA8290=y
CONFIG_MEDIA_TUNER_TDA9887=y
CONFIG_MEDIA_TUNER_TEA5761=y
CONFIG_MEDIA_TUNER_TEA5767=y
CONFIG_MEDIA_TUNER_TUA9001=y
CONFIG_MEDIA_TUNER_XC2028=y
CONFIG_MEDIA_TUNER_XC4000=y
CONFIG_MEDIA_TUNER_XC5000=y
# end of Customize TV tuners

#
# Customise DVB Frontends
#

#
# Multistandard (satellite) frontends
#
CONFIG_DVB_M88DS3103=y
CONFIG_DVB_MXL5XX=y
CONFIG_DVB_STB0899=y
CONFIG_DVB_STB6100=y
CONFIG_DVB_STV090x=y
CONFIG_DVB_STV0910=y
CONFIG_DVB_STV6110x=y
CONFIG_DVB_STV6111=y

#
# Multistandard (cable + terrestrial) frontends
#
CONFIG_DVB_DRXK=y
CONFIG_DVB_MN88472=y
CONFIG_DVB_MN88473=y
CONFIG_DVB_SI2165=y
CONFIG_DVB_TDA18271C2DD=y

#
# DVB-S (satellite) frontends
#
CONFIG_DVB_CX24110=y
CONFIG_DVB_CX24116=y
CONFIG_DVB_CX24117=y
CONFIG_DVB_CX24120=y
CONFIG_DVB_CX24123=y
CONFIG_DVB_DS3000=y
CONFIG_DVB_MB86A16=y
CONFIG_DVB_MT312=y
CONFIG_DVB_S5H1420=y
CONFIG_DVB_SI21XX=y
CONFIG_DVB_STB6000=y
CONFIG_DVB_STV0288=y
CONFIG_DVB_STV0299=y
CONFIG_DVB_STV0900=y
CONFIG_DVB_STV6110=y
CONFIG_DVB_TDA10071=y
CONFIG_DVB_TDA10086=y
CONFIG_DVB_TDA8083=y
CONFIG_DVB_TDA8261=y
CONFIG_DVB_TDA826X=y
CONFIG_DVB_TS2020=y
CONFIG_DVB_TUA6100=y
CONFIG_DVB_TUNER_CX24113=y
CONFIG_DVB_TUNER_ITD1000=y
CONFIG_DVB_VES1X93=y
CONFIG_DVB_ZL10036=y
CONFIG_DVB_ZL10039=y

#
# DVB-T (terrestrial) frontends
#
CONFIG_DVB_AF9013=y
CONFIG_DVB_AS102_FE=y
CONFIG_DVB_CX22700=y
CONFIG_DVB_CX22702=y
CONFIG_DVB_CXD2820R=y
CONFIG_DVB_CXD2841ER=y
CONFIG_DVB_DIB3000MB=y
CONFIG_DVB_DIB3000MC=y
CONFIG_DVB_DIB7000M=y
CONFIG_DVB_DIB7000P=y
CONFIG_DVB_DIB9000=y
CONFIG_DVB_DRXD=y
CONFIG_DVB_EC100=y
CONFIG_DVB_GP8PSK_FE=y
CONFIG_DVB_L64781=y
CONFIG_DVB_MT352=y
CONFIG_DVB_NXT6000=y
CONFIG_DVB_RTL2830=y
CONFIG_DVB_RTL2832=y
CONFIG_DVB_RTL2832_SDR=y
CONFIG_DVB_S5H1432=y
CONFIG_DVB_SI2168=y
CONFIG_DVB_SP887X=y
CONFIG_DVB_STV0367=y
CONFIG_DVB_TDA10048=y
CONFIG_DVB_TDA1004X=y
CONFIG_DVB_ZD1301_DEMOD=y
CONFIG_DVB_ZL10353=y
CONFIG_DVB_CXD2880=y

#
# DVB-C (cable) frontends
#
CONFIG_DVB_STV0297=y
CONFIG_DVB_TDA10021=y
CONFIG_DVB_TDA10023=y
CONFIG_DVB_VES1820=y

#
# ATSC (North American/Korean Terrestrial/Cable DTV) frontends
#
CONFIG_DVB_AU8522=y
CONFIG_DVB_AU8522_DTV=y
CONFIG_DVB_AU8522_V4L=y
CONFIG_DVB_BCM3510=y
CONFIG_DVB_LG2160=y
CONFIG_DVB_LGDT3305=y
CONFIG_DVB_LGDT3306A=y
CONFIG_DVB_LGDT330X=y
CONFIG_DVB_MXL692=y
CONFIG_DVB_NXT200X=y
CONFIG_DVB_OR51132=y
CONFIG_DVB_OR51211=y
CONFIG_DVB_S5H1409=y
CONFIG_DVB_S5H1411=y

#
# ISDB-T (terrestrial) frontends
#
CONFIG_DVB_DIB8000=y
CONFIG_DVB_MB86A20S=y
CONFIG_DVB_S921=y

#
# ISDB-S (satellite) & ISDB-T (terrestrial) frontends
#
CONFIG_DVB_MN88443X=y
CONFIG_DVB_TC90522=y

#
# Digital terrestrial only tuners/PLL
#
CONFIG_DVB_PLL=y
CONFIG_DVB_TUNER_DIB0070=y
CONFIG_DVB_TUNER_DIB0090=y

#
# SEC control devices for DVB-S
#
CONFIG_DVB_A8293=y
CONFIG_DVB_AF9033=y
CONFIG_DVB_ASCOT2E=y
CONFIG_DVB_ATBM8830=y
CONFIG_DVB_HELENE=y
CONFIG_DVB_HORUS3A=y
CONFIG_DVB_ISL6405=y
CONFIG_DVB_ISL6421=y
CONFIG_DVB_ISL6423=y
CONFIG_DVB_IX2505V=y
CONFIG_DVB_LGS8GL5=y
CONFIG_DVB_LGS8GXX=y
CONFIG_DVB_LNBH25=y
CONFIG_DVB_LNBH29=y
CONFIG_DVB_LNBP21=y
CONFIG_DVB_LNBP22=y
CONFIG_DVB_M88RS2000=y
CONFIG_DVB_TDA665x=y
CONFIG_DVB_DRX39XYJ=y

#
# Common Interface (EN50221) controller drivers
#
CONFIG_DVB_CXD2099=y
CONFIG_DVB_SP2=y
# end of Customise DVB Frontends

#
# Tools to develop new frontends
#
CONFIG_DVB_DUMMY_FE=y
# end of Media ancillary drivers

#
# Graphics support
#
CONFIG_APERTURE_HELPERS=y
CONFIG_AGP=y
CONFIG_AGP_AMD64=y
CONFIG_AGP_INTEL=y
CONFIG_AGP_SIS=y
CONFIG_AGP_VIA=y
CONFIG_INTEL_GTT=y
CONFIG_VGA_SWITCHEROO=y
CONFIG_DRM=y
CONFIG_DRM_MIPI_DBI=y
CONFIG_DRM_MIPI_DSI=y
CONFIG_DRM_DEBUG_MM=y
CONFIG_DRM_DEBUG_SELFTEST=y
CONFIG_DRM_KUNIT_TEST=y
CONFIG_DRM_KMS_HELPER=y
CONFIG_DRM_DEBUG_DP_MST_TOPOLOGY_REFS=y
CONFIG_DRM_DEBUG_MODESET_LOCK=y
CONFIG_DRM_FBDEV_EMULATION=y
CONFIG_DRM_FBDEV_OVERALLOC=100
CONFIG_DRM_FBDEV_LEAK_PHYS_SMEM=y
CONFIG_DRM_LOAD_EDID_FIRMWARE=y
CONFIG_DRM_DP_AUX_BUS=y
CONFIG_DRM_DISPLAY_HELPER=y
CONFIG_DRM_DISPLAY_DP_HELPER=y
CONFIG_DRM_DISPLAY_HDCP_HELPER=y
CONFIG_DRM_DISPLAY_HDMI_HELPER=y
CONFIG_DRM_DP_AUX_CHARDEV=y
CONFIG_DRM_DP_CEC=y
CONFIG_DRM_TTM=y
CONFIG_DRM_BUDDY=y
CONFIG_DRM_VRAM_HELPER=y
CONFIG_DRM_TTM_HELPER=y
CONFIG_DRM_GEM_CMA_HELPER=y
CONFIG_DRM_GEM_SHMEM_HELPER=y
CONFIG_DRM_SCHED=y

#
# I2C encoder or helper chips
#
CONFIG_DRM_I2C_CH7006=y
CONFIG_DRM_I2C_SIL164=y
CONFIG_DRM_I2C_NXP_TDA998X=y
CONFIG_DRM_I2C_NXP_TDA9950=y
# end of I2C encoder or helper chips

#
# ARM devices
#
CONFIG_DRM_KOMEDA=y
# end of ARM devices

CONFIG_DRM_RADEON=y
CONFIG_DRM_RADEON_USERPTR=y
CONFIG_DRM_AMDGPU=y
CONFIG_DRM_AMDGPU_SI=y
CONFIG_DRM_AMDGPU_CIK=y
CONFIG_DRM_AMDGPU_USERPTR=y

#
# ACP (Audio CoProcessor) Configuration
#
CONFIG_DRM_AMD_ACP=y
# end of ACP (Audio CoProcessor) Configuration

#
# Display Engine Configuration
#
CONFIG_DRM_AMD_DC=y
CONFIG_DRM_AMD_DC_DCN=y
CONFIG_DRM_AMD_DC_HDCP=y
CONFIG_DRM_AMD_DC_SI=y
CONFIG_DEBUG_KERNEL_DC=y
CONFIG_DRM_AMD_SECURE_DISPLAY=y
# end of Display Engine Configuration

CONFIG_HSA_AMD=y
CONFIG_HSA_AMD_SVM=y
CONFIG_HSA_AMD_P2P=y
CONFIG_DRM_NOUVEAU=y
CONFIG_NOUVEAU_LEGACY_CTX_SUPPORT=y
CONFIG_NOUVEAU_DEBUG=5
CONFIG_NOUVEAU_DEBUG_DEFAULT=3
CONFIG_NOUVEAU_DEBUG_MMU=y
CONFIG_NOUVEAU_DEBUG_PUSH=y
CONFIG_DRM_NOUVEAU_BACKLIGHT=y
CONFIG_DRM_NOUVEAU_SVM=y
CONFIG_DRM_I915=y
CONFIG_DRM_I915_FORCE_PROBE=""
CONFIG_DRM_I915_CAPTURE_ERROR=y
CONFIG_DRM_I915_COMPRESS_ERROR=y
CONFIG_DRM_I915_USERPTR=y
CONFIG_DRM_I915_GVT=y
CONFIG_DRM_I915_GVT_KVMGT=y
CONFIG_DRM_I915_PXP=y

#
# drm/i915 Debugging
#
CONFIG_DRM_I915_WERROR=y
# CONFIG_DRM_I915_DEBUG is not set
CONFIG_DRM_I915_DEBUG_MMIO=y
# CONFIG_DRM_I915_DEBUG_GEM is not set
CONFIG_DRM_I915_SW_FENCE_DEBUG_OBJECTS=y
CONFIG_DRM_I915_SW_FENCE_CHECK_DAG=y
CONFIG_DRM_I915_DEBUG_GUC=y
CONFIG_DRM_I915_SELFTEST=y
CONFIG_DRM_I915_LOW_LEVEL_TRACEPOINTS=y
CONFIG_DRM_I915_DEBUG_VBLANK_EVADE=y
CONFIG_DRM_I915_DEBUG_RUNTIME_PM=y
# end of drm/i915 Debugging

#
# drm/i915 Profile Guided Optimisation
#
CONFIG_DRM_I915_REQUEST_TIMEOUT=20000
CONFIG_DRM_I915_FENCE_TIMEOUT=10000
CONFIG_DRM_I915_USERFAULT_AUTOSUSPEND=250
CONFIG_DRM_I915_HEARTBEAT_INTERVAL=2500
CONFIG_DRM_I915_PREEMPT_TIMEOUT=640
CONFIG_DRM_I915_MAX_REQUEST_BUSYWAIT=8000
CONFIG_DRM_I915_STOP_TIMEOUT=100
CONFIG_DRM_I915_TIMESLICE_DURATION=1
# end of drm/i915 Profile Guided Optimisation

CONFIG_DRM_VGEM=y
CONFIG_DRM_VKMS=y
CONFIG_DRM_VMWGFX=y
CONFIG_DRM_VMWGFX_FBCON=y
CONFIG_DRM_VMWGFX_MKSSTATS=y
CONFIG_DRM_GMA500=y
CONFIG_DRM_UDL=y
CONFIG_DRM_AST=y
CONFIG_DRM_MGAG200=y
CONFIG_DRM_RCAR_DW_HDMI=y
CONFIG_DRM_RCAR_USE_LVDS=y
CONFIG_DRM_RCAR_MIPI_DSI=y
CONFIG_DRM_QXL=y
CONFIG_DRM_VIRTIO_GPU=y
CONFIG_DRM_PANEL=y

#
# Display Panels
#
CONFIG_DRM_PANEL_ABT_Y030XX067A=y
CONFIG_DRM_PANEL_ARM_VERSATILE=y
CONFIG_DRM_PANEL_ASUS_Z00T_TM5P5_NT35596=y
CONFIG_DRM_PANEL_BOE_BF060Y8M_AJ0=y
CONFIG_DRM_PANEL_BOE_HIMAX8279D=y
CONFIG_DRM_PANEL_BOE_TV101WUM_NL6=y
CONFIG_DRM_PANEL_DSI_CM=y
CONFIG_DRM_PANEL_LVDS=y
CONFIG_DRM_PANEL_SIMPLE=y
CONFIG_DRM_PANEL_EDP=y
CONFIG_DRM_PANEL_EBBG_FT8719=y
CONFIG_DRM_PANEL_ELIDA_KD35T133=y
CONFIG_DRM_PANEL_FEIXIN_K101_IM2BA02=y
CONFIG_DRM_PANEL_FEIYANG_FY07024DI26A30D=y
CONFIG_DRM_PANEL_ILITEK_IL9322=y
CONFIG_DRM_PANEL_ILITEK_ILI9341=y
CONFIG_DRM_PANEL_ILITEK_ILI9881C=y
CONFIG_DRM_PANEL_INNOLUX_EJ030NA=y
CONFIG_DRM_PANEL_INNOLUX_P079ZCA=y
CONFIG_DRM_PANEL_JDI_LT070ME05000=y
CONFIG_DRM_PANEL_JDI_R63452=y
CONFIG_DRM_PANEL_KHADAS_TS050=y
CONFIG_DRM_PANEL_KINGDISPLAY_KD097D04=y
CONFIG_DRM_PANEL_LEADTEK_LTK050H3146W=y
CONFIG_DRM_PANEL_LEADTEK_LTK500HD1829=y
CONFIG_DRM_PANEL_SAMSUNG_LD9040=y
CONFIG_DRM_PANEL_LG_LB035Q02=y
CONFIG_DRM_PANEL_LG_LG4573=y
CONFIG_DRM_PANEL_NEC_NL8048HL11=y
CONFIG_DRM_PANEL_NEWVISION_NV3052C=y
CONFIG_DRM_PANEL_NOVATEK_NT35510=y
CONFIG_DRM_PANEL_NOVATEK_NT35560=y
CONFIG_DRM_PANEL_NOVATEK_NT35950=y
CONFIG_DRM_PANEL_NOVATEK_NT36672A=y
CONFIG_DRM_PANEL_NOVATEK_NT39016=y
CONFIG_DRM_PANEL_MANTIX_MLAF057WE51=y
CONFIG_DRM_PANEL_OLIMEX_LCD_OLINUXINO=y
CONFIG_DRM_PANEL_ORISETECH_OTM8009A=y
CONFIG_DRM_PANEL_OSD_OSD101T2587_53TS=y
CONFIG_DRM_PANEL_PANASONIC_VVX10F034N00=y
CONFIG_DRM_PANEL_RASPBERRYPI_TOUCHSCREEN=y
CONFIG_DRM_PANEL_RAYDIUM_RM67191=y
CONFIG_DRM_PANEL_RAYDIUM_RM68200=y
CONFIG_DRM_PANEL_RONBO_RB070D30=y
CONFIG_DRM_PANEL_SAMSUNG_ATNA33XC20=y
CONFIG_DRM_PANEL_SAMSUNG_DB7430=y
CONFIG_DRM_PANEL_SAMSUNG_S6D16D0=y
CONFIG_DRM_PANEL_SAMSUNG_S6D27A1=y
CONFIG_DRM_PANEL_SAMSUNG_S6E3HA2=y
CONFIG_DRM_PANEL_SAMSUNG_S6E63J0X03=y
CONFIG_DRM_PANEL_SAMSUNG_S6E63M0=y
CONFIG_DRM_PANEL_SAMSUNG_S6E63M0_SPI=y
CONFIG_DRM_PANEL_SAMSUNG_S6E63M0_DSI=y
CONFIG_DRM_PANEL_SAMSUNG_S6E88A0_AMS452EF01=y
CONFIG_DRM_PANEL_SAMSUNG_S6E8AA0=y
CONFIG_DRM_PANEL_SAMSUNG_SOFEF00=y
CONFIG_DRM_PANEL_SEIKO_43WVF1G=y
CONFIG_DRM_PANEL_SHARP_LQ101R1SX01=y
CONFIG_DRM_PANEL_SHARP_LS037V7DW01=y
CONFIG_DRM_PANEL_SHARP_LS043T1LE01=y
CONFIG_DRM_PANEL_SHARP_LS060T1SX01=y
CONFIG_DRM_PANEL_SITRONIX_ST7701=y
CONFIG_DRM_PANEL_SITRONIX_ST7703=y
CONFIG_DRM_PANEL_SITRONIX_ST7789V=y
CONFIG_DRM_PANEL_SONY_ACX565AKM=y
CONFIG_DRM_PANEL_SONY_TULIP_TRULY_NT35521=y
CONFIG_DRM_PANEL_TDO_TL070WSH30=y
CONFIG_DRM_PANEL_TPO_TD028TTEC1=y
CONFIG_DRM_PANEL_TPO_TD043MTEA1=y
CONFIG_DRM_PANEL_TPO_TPG110=y
CONFIG_DRM_PANEL_TRULY_NT35597_WQXGA=y
CONFIG_DRM_PANEL_VISIONOX_RM69299=y
CONFIG_DRM_PANEL_WIDECHIPS_WS2401=y
CONFIG_DRM_PANEL_XINPENG_XPP055C272=y
# end of Display Panels

CONFIG_DRM_BRIDGE=y
CONFIG_DRM_PANEL_BRIDGE=y

#
# Display Interface Bridges
#
CONFIG_DRM_CDNS_DSI=y
CONFIG_DRM_CHIPONE_ICN6211=y
CONFIG_DRM_CHRONTEL_CH7033=y
CONFIG_DRM_CROS_EC_ANX7688=y
CONFIG_DRM_DISPLAY_CONNECTOR=y
CONFIG_DRM_ITE_IT6505=y
CONFIG_DRM_LONTIUM_LT8912B=y
CONFIG_DRM_LONTIUM_LT9211=y
CONFIG_DRM_LONTIUM_LT9611=y
CONFIG_DRM_LONTIUM_LT9611UXC=y
CONFIG_DRM_ITE_IT66121=y
CONFIG_DRM_LVDS_CODEC=y
CONFIG_DRM_MEGACHIPS_STDPXXXX_GE_B850V3_FW=y
CONFIG_DRM_NWL_MIPI_DSI=y
CONFIG_DRM_NXP_PTN3460=y
CONFIG_DRM_PARADE_PS8622=y
CONFIG_DRM_PARADE_PS8640=y
CONFIG_DRM_SIL_SII8620=y
CONFIG_DRM_SII902X=y
CONFIG_DRM_SII9234=y
CONFIG_DRM_SIMPLE_BRIDGE=y
CONFIG_DRM_THINE_THC63LVD1024=y
CONFIG_DRM_TOSHIBA_TC358762=y
CONFIG_DRM_TOSHIBA_TC358764=y
CONFIG_DRM_TOSHIBA_TC358767=y
CONFIG_DRM_TOSHIBA_TC358768=y
CONFIG_DRM_TOSHIBA_TC358775=y
CONFIG_DRM_TI_DLPC3433=y
CONFIG_DRM_TI_TFP410=y
CONFIG_DRM_TI_SN65DSI83=y
CONFIG_DRM_TI_SN65DSI86=y
CONFIG_DRM_TI_TPD12S015=y
CONFIG_DRM_ANALOGIX_ANX6345=y
CONFIG_DRM_ANALOGIX_ANX78XX=y
CONFIG_DRM_ANALOGIX_DP=y
CONFIG_DRM_ANALOGIX_ANX7625=y
CONFIG_DRM_I2C_ADV7511=y
CONFIG_DRM_I2C_ADV7511_AUDIO=y
CONFIG_DRM_I2C_ADV7511_CEC=y
CONFIG_DRM_CDNS_MHDP8546=y
CONFIG_DRM_DW_HDMI=y
CONFIG_DRM_DW_HDMI_AHB_AUDIO=y
CONFIG_DRM_DW_HDMI_I2S_AUDIO=y
CONFIG_DRM_DW_HDMI_GP_AUDIO=y
CONFIG_DRM_DW_HDMI_CEC=y
# end of Display Interface Bridges

CONFIG_DRM_ETNAVIV=y
CONFIG_DRM_ETNAVIV_THERMAL=y
CONFIG_DRM_LOGICVC=y
CONFIG_DRM_MXS=y
CONFIG_DRM_MXSFB=y
CONFIG_DRM_IMX_LCDIF=y
CONFIG_DRM_ARCPGU=y
CONFIG_DRM_BOCHS=y
CONFIG_DRM_CIRRUS_QEMU=y
CONFIG_DRM_GM12U320=y
CONFIG_DRM_PANEL_MIPI_DBI=y
CONFIG_DRM_SIMPLEDRM=y
CONFIG_TINYDRM_HX8357D=y
CONFIG_TINYDRM_ILI9163=y
CONFIG_TINYDRM_ILI9225=y
CONFIG_TINYDRM_ILI9341=y
CONFIG_TINYDRM_ILI9486=y
CONFIG_TINYDRM_MI0283QT=y
CONFIG_TINYDRM_REPAPER=y
CONFIG_TINYDRM_ST7586=y
CONFIG_TINYDRM_ST7735R=y
CONFIG_DRM_XEN=y
CONFIG_DRM_XEN_FRONTEND=y
CONFIG_DRM_VBOXVIDEO=y
CONFIG_DRM_GUD=y
CONFIG_DRM_SSD130X=y
CONFIG_DRM_SSD130X_I2C=y
CONFIG_DRM_SSD130X_SPI=y
CONFIG_DRM_HYPERV=y
CONFIG_DRM_LEGACY=y
CONFIG_DRM_TDFX=y
CONFIG_DRM_R128=y
CONFIG_DRM_MGA=y
CONFIG_DRM_SIS=y
CONFIG_DRM_VIA=y
CONFIG_DRM_SAVAGE=y
CONFIG_DRM_EXPORT_FOR_TESTS=y
CONFIG_DRM_PANEL_ORIENTATION_QUIRKS=y
CONFIG_DRM_NOMODESET=y
CONFIG_DRM_LIB_RANDOM=y
CONFIG_DRM_PRIVACY_SCREEN=y

#
# Frame buffer Devices
#
CONFIG_FB_CMDLINE=y
CONFIG_FB_NOTIFY=y
CONFIG_FB=y
CONFIG_FIRMWARE_EDID=y
CONFIG_FB_DDC=y
CONFIG_FB_CFB_FILLRECT=y
CONFIG_FB_CFB_COPYAREA=y
CONFIG_FB_CFB_IMAGEBLIT=y
CONFIG_FB_SYS_FILLRECT=y
CONFIG_FB_SYS_COPYAREA=y
CONFIG_FB_SYS_IMAGEBLIT=y
CONFIG_FB_FOREIGN_ENDIAN=y
CONFIG_FB_BOTH_ENDIAN=y
# CONFIG_FB_BIG_ENDIAN is not set
# CONFIG_FB_LITTLE_ENDIAN is not set
CONFIG_FB_SYS_FOPS=y
CONFIG_FB_DEFERRED_IO=y
CONFIG_FB_HECUBA=y
CONFIG_FB_SVGALIB=y
CONFIG_FB_BACKLIGHT=y
CONFIG_FB_MODE_HELPERS=y
CONFIG_FB_TILEBLITTING=y

#
# Frame buffer hardware drivers
#
CONFIG_FB_CIRRUS=y
CONFIG_FB_PM2=y
CONFIG_FB_PM2_FIFO_DISCONNECT=y
CONFIG_FB_CYBER2000=y
CONFIG_FB_CYBER2000_DDC=y
CONFIG_FB_ARC=y
CONFIG_FB_ASILIANT=y
CONFIG_FB_IMSTT=y
CONFIG_FB_VGA16=y
CONFIG_FB_UVESA=y
CONFIG_FB_VESA=y
CONFIG_FB_EFI=y
CONFIG_FB_N411=y
CONFIG_FB_HGA=y
CONFIG_FB_OPENCORES=y
CONFIG_FB_S1D13XXX=y
CONFIG_FB_NVIDIA=y
CONFIG_FB_NVIDIA_I2C=y
CONFIG_FB_NVIDIA_DEBUG=y
CONFIG_FB_NVIDIA_BACKLIGHT=y
CONFIG_FB_RIVA=y
CONFIG_FB_RIVA_I2C=y
CONFIG_FB_RIVA_DEBUG=y
CONFIG_FB_RIVA_BACKLIGHT=y
CONFIG_FB_I740=y
CONFIG_FB_LE80578=y
CONFIG_FB_CARILLO_RANCH=y
CONFIG_FB_MATROX=y
CONFIG_FB_MATROX_MILLENIUM=y
CONFIG_FB_MATROX_MYSTIQUE=y
CONFIG_FB_MATROX_G=y
CONFIG_FB_MATROX_I2C=y
CONFIG_FB_MATROX_MAVEN=y
CONFIG_FB_RADEON=y
CONFIG_FB_RADEON_I2C=y
CONFIG_FB_RADEON_BACKLIGHT=y
CONFIG_FB_RADEON_DEBUG=y
CONFIG_FB_ATY128=y
CONFIG_FB_ATY128_BACKLIGHT=y
CONFIG_FB_ATY=y
CONFIG_FB_ATY_CT=y
CONFIG_FB_ATY_GENERIC_LCD=y
CONFIG_FB_ATY_GX=y
CONFIG_FB_ATY_BACKLIGHT=y
CONFIG_FB_S3=y
CONFIG_FB_S3_DDC=y
CONFIG_FB_SAVAGE=y
CONFIG_FB_SAVAGE_I2C=y
CONFIG_FB_SAVAGE_ACCEL=y
CONFIG_FB_SIS=y
CONFIG_FB_SIS_300=y
CONFIG_FB_SIS_315=y
CONFIG_FB_VIA=y
CONFIG_FB_VIA_DIRECT_PROCFS=y
CONFIG_FB_VIA_X_COMPATIBILITY=y
CONFIG_FB_NEOMAGIC=y
CONFIG_FB_KYRO=y
CONFIG_FB_3DFX=y
CONFIG_FB_3DFX_ACCEL=y
CONFIG_FB_3DFX_I2C=y
CONFIG_FB_VOODOO1=y
CONFIG_FB_VT8623=y
CONFIG_FB_TRIDENT=y
CONFIG_FB_ARK=y
CONFIG_FB_PM3=y
CONFIG_FB_CARMINE=y
CONFIG_FB_CARMINE_DRAM_EVAL=y
# CONFIG_CARMINE_DRAM_CUSTOM is not set
CONFIG_FB_SM501=y
CONFIG_FB_SMSCUFX=y
CONFIG_FB_UDL=y
CONFIG_FB_IBM_GXT4500=y
CONFIG_FB_GOLDFISH=y
CONFIG_FB_VIRTUAL=y
CONFIG_XEN_FBDEV_FRONTEND=y
CONFIG_FB_METRONOME=y
CONFIG_FB_MB862XX=y
CONFIG_FB_MB862XX_PCI_GDC=y
CONFIG_FB_MB862XX_I2C=y
CONFIG_FB_HYPERV=y
CONFIG_FB_SSD1307=y
CONFIG_FB_SM712=y
# end of Frame buffer Devices

#
# Backlight & LCD device support
#
CONFIG_LCD_CLASS_DEVICE=y
CONFIG_LCD_L4F00242T03=y
CONFIG_LCD_LMS283GF05=y
CONFIG_LCD_LTV350QV=y
CONFIG_LCD_ILI922X=y
CONFIG_LCD_ILI9320=y
CONFIG_LCD_TDO24M=y
CONFIG_LCD_VGG2432A4=y
CONFIG_LCD_PLATFORM=y
CONFIG_LCD_AMS369FG06=y
CONFIG_LCD_LMS501KF03=y
CONFIG_LCD_HX8357=y
CONFIG_LCD_OTM3225A=y
CONFIG_BACKLIGHT_CLASS_DEVICE=y
CONFIG_BACKLIGHT_KTD253=y
CONFIG_BACKLIGHT_LM3533=y
CONFIG_BACKLIGHT_CARILLO_RANCH=y
CONFIG_BACKLIGHT_PWM=y
CONFIG_BACKLIGHT_DA903X=y
CONFIG_BACKLIGHT_DA9052=y
CONFIG_BACKLIGHT_MAX8925=y
CONFIG_BACKLIGHT_APPLE=y
CONFIG_BACKLIGHT_QCOM_WLED=y
CONFIG_BACKLIGHT_RT4831=y
CONFIG_BACKLIGHT_SAHARA=y
CONFIG_BACKLIGHT_WM831X=y
CONFIG_BACKLIGHT_ADP5520=y
CONFIG_BACKLIGHT_ADP8860=y
CONFIG_BACKLIGHT_ADP8870=y
CONFIG_BACKLIGHT_88PM860X=y
CONFIG_BACKLIGHT_PCF50633=y
CONFIG_BACKLIGHT_AAT2870=y
CONFIG_BACKLIGHT_LM3630A=y
CONFIG_BACKLIGHT_LM3639=y
CONFIG_BACKLIGHT_LP855X=y
CONFIG_BACKLIGHT_LP8788=y
CONFIG_BACKLIGHT_PANDORA=y
CONFIG_BACKLIGHT_SKY81452=y
CONFIG_BACKLIGHT_TPS65217=y
CONFIG_BACKLIGHT_AS3711=y
CONFIG_BACKLIGHT_GPIO=y
CONFIG_BACKLIGHT_LV5207LP=y
CONFIG_BACKLIGHT_BD6107=y
CONFIG_BACKLIGHT_ARCXCNN=y
CONFIG_BACKLIGHT_RAVE_SP=y
CONFIG_BACKLIGHT_LED=y
# end of Backlight & LCD device support

CONFIG_VGASTATE=y
CONFIG_VIDEOMODE_HELPERS=y
CONFIG_HDMI=y

#
# Console display driver support
#
CONFIG_VGA_CONSOLE=y
CONFIG_DUMMY_CONSOLE=y
CONFIG_DUMMY_CONSOLE_COLUMNS=80
CONFIG_DUMMY_CONSOLE_ROWS=25
CONFIG_FRAMEBUFFER_CONSOLE=y
CONFIG_FRAMEBUFFER_CONSOLE_LEGACY_ACCELERATION=y
CONFIG_FRAMEBUFFER_CONSOLE_DETECT_PRIMARY=y
CONFIG_FRAMEBUFFER_CONSOLE_ROTATION=y
CONFIG_FRAMEBUFFER_CONSOLE_DEFERRED_TAKEOVER=y
# end of Console display driver support

CONFIG_LOGO=y
CONFIG_LOGO_LINUX_MONO=y
CONFIG_LOGO_LINUX_VGA16=y
CONFIG_LOGO_LINUX_CLUT224=y
# end of Graphics support

CONFIG_SOUND=y
CONFIG_SOUND_OSS_CORE=y
CONFIG_SOUND_OSS_CORE_PRECLAIM=y
CONFIG_SND=y
CONFIG_SND_TIMER=y
CONFIG_SND_PCM=y
CONFIG_SND_PCM_ELD=y
CONFIG_SND_PCM_IEC958=y
CONFIG_SND_DMAENGINE_PCM=y
CONFIG_SND_HWDEP=y
CONFIG_SND_SEQ_DEVICE=y
CONFIG_SND_RAWMIDI=y
CONFIG_SND_COMPRESS_OFFLOAD=y
CONFIG_SND_JACK=y
CONFIG_SND_JACK_INPUT_DEV=y
CONFIG_SND_OSSEMUL=y
CONFIG_SND_MIXER_OSS=y
CONFIG_SND_PCM_OSS=y
CONFIG_SND_PCM_OSS_PLUGINS=y
CONFIG_SND_PCM_TIMER=y
CONFIG_SND_HRTIMER=y
CONFIG_SND_DYNAMIC_MINORS=y
CONFIG_SND_MAX_CARDS=32
CONFIG_SND_SUPPORT_OLD_API=y
CONFIG_SND_PROC_FS=y
CONFIG_SND_VERBOSE_PROCFS=y
CONFIG_SND_VERBOSE_PRINTK=y
CONFIG_SND_CTL_FAST_LOOKUP=y
CONFIG_SND_DEBUG=y
CONFIG_SND_DEBUG_VERBOSE=y
CONFIG_SND_PCM_XRUN_DEBUG=y
CONFIG_SND_CTL_INPUT_VALIDATION=y
CONFIG_SND_CTL_DEBUG=y
CONFIG_SND_JACK_INJECTION_DEBUG=y
CONFIG_SND_VMASTER=y
CONFIG_SND_DMA_SGBUF=y
CONFIG_SND_CTL_LED=y
CONFIG_SND_SEQUENCER=y
CONFIG_SND_SEQ_DUMMY=y
CONFIG_SND_SEQUENCER_OSS=y
CONFIG_SND_SEQ_HRTIMER_DEFAULT=y
CONFIG_SND_SEQ_MIDI_EVENT=y
CONFIG_SND_SEQ_MIDI=y
CONFIG_SND_SEQ_MIDI_EMUL=y
CONFIG_SND_SEQ_VIRMIDI=y
CONFIG_SND_MPU401_UART=y
CONFIG_SND_OPL3_LIB=y
CONFIG_SND_OPL3_LIB_SEQ=y
CONFIG_SND_VX_LIB=y
CONFIG_SND_AC97_CODEC=y
CONFIG_SND_DRIVERS=y
CONFIG_SND_PCSP=y
CONFIG_SND_DUMMY=y
CONFIG_SND_ALOOP=y
CONFIG_SND_VIRMIDI=y
CONFIG_SND_MTPAV=y
CONFIG_SND_MTS64=y
CONFIG_SND_SERIAL_U16550=y
CONFIG_SND_SERIAL_GENERIC=y
CONFIG_SND_MPU401=y
CONFIG_SND_PORTMAN2X4=y
CONFIG_SND_AC97_POWER_SAVE=y
CONFIG_SND_AC97_POWER_SAVE_DEFAULT=0
CONFIG_SND_SB_COMMON=y
CONFIG_SND_PCI=y
CONFIG_SND_AD1889=y
CONFIG_SND_ALS300=y
CONFIG_SND_ALS4000=y
CONFIG_SND_ALI5451=y
CONFIG_SND_ASIHPI=y
CONFIG_SND_ATIIXP=y
CONFIG_SND_ATIIXP_MODEM=y
CONFIG_SND_AU8810=y
CONFIG_SND_AU8820=y
CONFIG_SND_AU8830=y
CONFIG_SND_AW2=y
CONFIG_SND_AZT3328=y
CONFIG_SND_BT87X=y
CONFIG_SND_BT87X_OVERCLOCK=y
CONFIG_SND_CA0106=y
CONFIG_SND_CMIPCI=y
CONFIG_SND_OXYGEN_LIB=y
CONFIG_SND_OXYGEN=y
CONFIG_SND_CS4281=y
CONFIG_SND_CS46XX=y
CONFIG_SND_CS46XX_NEW_DSP=y
CONFIG_SND_CTXFI=y
CONFIG_SND_DARLA20=y
CONFIG_SND_GINA20=y
CONFIG_SND_LAYLA20=y
CONFIG_SND_DARLA24=y
CONFIG_SND_GINA24=y
CONFIG_SND_LAYLA24=y
CONFIG_SND_MONA=y
CONFIG_SND_MIA=y
CONFIG_SND_ECHO3G=y
CONFIG_SND_INDIGO=y
CONFIG_SND_INDIGOIO=y
CONFIG_SND_INDIGODJ=y
CONFIG_SND_INDIGOIOX=y
CONFIG_SND_INDIGODJX=y
CONFIG_SND_EMU10K1=y
CONFIG_SND_EMU10K1_SEQ=y
CONFIG_SND_EMU10K1X=y
CONFIG_SND_ENS1370=y
CONFIG_SND_ENS1371=y
CONFIG_SND_ES1938=y
CONFIG_SND_ES1968=y
CONFIG_SND_ES1968_INPUT=y
CONFIG_SND_ES1968_RADIO=y
CONFIG_SND_FM801=y
CONFIG_SND_FM801_TEA575X_BOOL=y
CONFIG_SND_HDSP=y

#
# Don't forget to add built-in firmwares for HDSP driver
#
CONFIG_SND_HDSPM=y
CONFIG_SND_ICE1712=y
CONFIG_SND_ICE1724=y
CONFIG_SND_INTEL8X0=y
CONFIG_SND_INTEL8X0M=y
CONFIG_SND_KORG1212=y
CONFIG_SND_LOLA=y
CONFIG_SND_LX6464ES=y
CONFIG_SND_MAESTRO3=y
CONFIG_SND_MAESTRO3_INPUT=y
CONFIG_SND_MIXART=y
CONFIG_SND_NM256=y
CONFIG_SND_PCXHR=y
CONFIG_SND_RIPTIDE=y
CONFIG_SND_RME32=y
CONFIG_SND_RME96=y
CONFIG_SND_RME9652=y
CONFIG_SND_SONICVIBES=y
CONFIG_SND_TRIDENT=y
CONFIG_SND_VIA82XX=y
CONFIG_SND_VIA82XX_MODEM=y
CONFIG_SND_VIRTUOSO=y
CONFIG_SND_VX222=y
CONFIG_SND_YMFPCI=y

#
# HD-Audio
#
CONFIG_SND_HDA=y
CONFIG_SND_HDA_GENERIC_LEDS=y
CONFIG_SND_HDA_INTEL=y
CONFIG_SND_HDA_HWDEP=y
CONFIG_SND_HDA_RECONFIG=y
CONFIG_SND_HDA_INPUT_BEEP=y
CONFIG_SND_HDA_INPUT_BEEP_MODE=1
CONFIG_SND_HDA_PATCH_LOADER=y
CONFIG_SND_HDA_SCODEC_CS35L41=y
CONFIG_SND_HDA_CS_DSP_CONTROLS=y
CONFIG_SND_HDA_SCODEC_CS35L41_I2C=y
CONFIG_SND_HDA_SCODEC_CS35L41_SPI=y
CONFIG_SND_HDA_CODEC_REALTEK=y
CONFIG_SND_HDA_CODEC_ANALOG=y
CONFIG_SND_HDA_CODEC_SIGMATEL=y
CONFIG_SND_HDA_CODEC_VIA=y
CONFIG_SND_HDA_CODEC_HDMI=y
CONFIG_SND_HDA_CODEC_CIRRUS=y
CONFIG_SND_HDA_CODEC_CS8409=y
CONFIG_SND_HDA_CODEC_CONEXANT=y
CONFIG_SND_HDA_CODEC_CA0110=y
CONFIG_SND_HDA_CODEC_CA0132=y
CONFIG_SND_HDA_CODEC_CA0132_DSP=y
CONFIG_SND_HDA_CODEC_CMEDIA=y
CONFIG_SND_HDA_CODEC_SI3054=y
CONFIG_SND_HDA_GENERIC=y
CONFIG_SND_HDA_POWER_SAVE_DEFAULT=0
CONFIG_SND_HDA_INTEL_HDMI_SILENT_STREAM=y
# end of HD-Audio

CONFIG_SND_HDA_CORE=y
CONFIG_SND_HDA_DSP_LOADER=y
CONFIG_SND_HDA_COMPONENT=y
CONFIG_SND_HDA_I915=y
CONFIG_SND_HDA_EXT_CORE=y
CONFIG_SND_HDA_PREALLOC_SIZE=0
CONFIG_SND_INTEL_NHLT=y
CONFIG_SND_INTEL_DSP_CONFIG=y
CONFIG_SND_INTEL_SOUNDWIRE_ACPI=y
CONFIG_SND_INTEL_BYT_PREFER_SOF=y
CONFIG_SND_SPI=y
CONFIG_SND_USB=y
CONFIG_SND_USB_AUDIO=y
CONFIG_SND_USB_AUDIO_USE_MEDIA_CONTROLLER=y
CONFIG_SND_USB_UA101=y
CONFIG_SND_USB_USX2Y=y
CONFIG_SND_USB_CAIAQ=y
CONFIG_SND_USB_CAIAQ_INPUT=y
CONFIG_SND_USB_US122L=y
CONFIG_SND_USB_6FIRE=y
CONFIG_SND_USB_HIFACE=y
CONFIG_SND_BCD2000=y
CONFIG_SND_USB_LINE6=y
CONFIG_SND_USB_POD=y
CONFIG_SND_USB_PODHD=y
CONFIG_SND_USB_TONEPORT=y
CONFIG_SND_USB_VARIAX=y
CONFIG_SND_FIREWIRE=y
CONFIG_SND_FIREWIRE_LIB=y
CONFIG_SND_DICE=y
CONFIG_SND_OXFW=y
CONFIG_SND_ISIGHT=y
CONFIG_SND_FIREWORKS=y
CONFIG_SND_BEBOB=y
CONFIG_SND_FIREWIRE_DIGI00X=y
CONFIG_SND_FIREWIRE_TASCAM=y
CONFIG_SND_FIREWIRE_MOTU=y
CONFIG_SND_FIREFACE=y
CONFIG_SND_PCMCIA=y
CONFIG_SND_VXPOCKET=y
CONFIG_SND_PDAUDIOCF=y
CONFIG_SND_SOC=y
CONFIG_SND_SOC_AC97_BUS=y
CONFIG_SND_SOC_GENERIC_DMAENGINE_PCM=y
CONFIG_SND_SOC_COMPRESS=y
CONFIG_SND_SOC_TOPOLOGY=y
CONFIG_SND_SOC_TOPOLOGY_KUNIT_TEST=y
CONFIG_SND_SOC_UTILS_KUNIT_TEST=y
CONFIG_SND_SOC_ACPI=y
CONFIG_SND_SOC_ADI=y
CONFIG_SND_SOC_ADI_AXI_I2S=y
CONFIG_SND_SOC_ADI_AXI_SPDIF=y
CONFIG_SND_SOC_AMD_ACP=y
CONFIG_SND_SOC_AMD_CZ_DA7219MX98357_MACH=y
CONFIG_SND_SOC_AMD_CZ_RT5645_MACH=y
CONFIG_SND_SOC_AMD_ST_ES8336_MACH=y
CONFIG_SND_SOC_AMD_ACP3x=y
CONFIG_SND_SOC_AMD_RV_RT5682_MACH=y
CONFIG_SND_SOC_AMD_RENOIR=y
CONFIG_SND_SOC_AMD_RENOIR_MACH=y
CONFIG_SND_SOC_AMD_ACP5x=y
CONFIG_SND_SOC_AMD_VANGOGH_MACH=y
CONFIG_SND_SOC_AMD_ACP6x=y
CONFIG_SND_SOC_AMD_YC_MACH=y
CONFIG_SND_AMD_ACP_CONFIG=y
CONFIG_SND_SOC_AMD_ACP_COMMON=y
CONFIG_SND_SOC_AMD_ACP_PDM=y
CONFIG_SND_SOC_AMD_ACP_I2S=y
CONFIG_SND_SOC_AMD_ACP_PCM=y
CONFIG_SND_SOC_AMD_ACP_PCI=y
CONFIG_SND_AMD_ASOC_RENOIR=y
CONFIG_SND_AMD_ASOC_REMBRANDT=y
CONFIG_SND_SOC_AMD_MACH_COMMON=y
CONFIG_SND_SOC_AMD_LEGACY_MACH=y
CONFIG_SND_SOC_AMD_SOF_MACH=y
CONFIG_SND_SOC_AMD_RPL_ACP6x=y
CONFIG_SND_ATMEL_SOC=y
CONFIG_SND_SOC_MIKROE_PROTO=y
CONFIG_SND_BCM63XX_I2S_WHISTLER=y
CONFIG_SND_DESIGNWARE_I2S=y
CONFIG_SND_DESIGNWARE_PCM=y

#
# SoC Audio for Freescale CPUs
#

#
# Common SoC Audio options for Freescale CPUs:
#
CONFIG_SND_SOC_FSL_ASRC=y
CONFIG_SND_SOC_FSL_SAI=y
CONFIG_SND_SOC_FSL_MQS=y
CONFIG_SND_SOC_FSL_AUDMIX=y
CONFIG_SND_SOC_FSL_SSI=y
CONFIG_SND_SOC_FSL_SPDIF=y
CONFIG_SND_SOC_FSL_ESAI=y
CONFIG_SND_SOC_FSL_MICFIL=y
CONFIG_SND_SOC_FSL_EASRC=y
CONFIG_SND_SOC_FSL_XCVR=y
CONFIG_SND_SOC_FSL_UTILS=y
CONFIG_SND_SOC_FSL_RPMSG=y
CONFIG_SND_SOC_IMX_AUDMUX=y
# end of SoC Audio for Freescale CPUs

CONFIG_SND_I2S_HI6210_I2S=y
CONFIG_SND_SOC_IMG=y
CONFIG_SND_SOC_IMG_I2S_IN=y
CONFIG_SND_SOC_IMG_I2S_OUT=y
CONFIG_SND_SOC_IMG_PARALLEL_OUT=y
CONFIG_SND_SOC_IMG_SPDIF_IN=y
CONFIG_SND_SOC_IMG_SPDIF_OUT=y
CONFIG_SND_SOC_IMG_PISTACHIO_INTERNAL_DAC=y
CONFIG_SND_SOC_INTEL_SST_TOPLEVEL=y
CONFIG_SND_SOC_INTEL_SST=y
CONFIG_SND_SOC_INTEL_CATPT=y
CONFIG_SND_SST_ATOM_HIFI2_PLATFORM=y
CONFIG_SND_SST_ATOM_HIFI2_PLATFORM_PCI=y
CONFIG_SND_SST_ATOM_HIFI2_PLATFORM_ACPI=y
CONFIG_SND_SOC_INTEL_SKYLAKE=y
CONFIG_SND_SOC_INTEL_SKL=y
CONFIG_SND_SOC_INTEL_APL=y
CONFIG_SND_SOC_INTEL_KBL=y
CONFIG_SND_SOC_INTEL_GLK=y
CONFIG_SND_SOC_INTEL_CNL=y
CONFIG_SND_SOC_INTEL_CFL=y
CONFIG_SND_SOC_INTEL_CML_H=y
CONFIG_SND_SOC_INTEL_CML_LP=y
CONFIG_SND_SOC_INTEL_SKYLAKE_FAMILY=y
CONFIG_SND_SOC_INTEL_SKYLAKE_SSP_CLK=y
CONFIG_SND_SOC_INTEL_SKYLAKE_HDAUDIO_CODEC=y
CONFIG_SND_SOC_INTEL_SKYLAKE_COMMON=y
CONFIG_SND_SOC_ACPI_INTEL_MATCH=y
CONFIG_SND_SOC_INTEL_AVS=y

#
# Intel AVS Machine drivers
#

#
# Available DSP configurations
#
CONFIG_SND_SOC_INTEL_AVS_MACH_DA7219=y
CONFIG_SND_SOC_INTEL_AVS_MACH_DMIC=y
CONFIG_SND_SOC_INTEL_AVS_MACH_HDAUDIO=y
CONFIG_SND_SOC_INTEL_AVS_MACH_I2S_TEST=y
CONFIG_SND_SOC_INTEL_AVS_MACH_MAX98357A=y
CONFIG_SND_SOC_INTEL_AVS_MACH_MAX98373=y
CONFIG_SND_SOC_INTEL_AVS_MACH_NAU8825=y
CONFIG_SND_SOC_INTEL_AVS_MACH_RT274=y
CONFIG_SND_SOC_INTEL_AVS_MACH_RT286=y
CONFIG_SND_SOC_INTEL_AVS_MACH_RT298=y
CONFIG_SND_SOC_INTEL_AVS_MACH_RT5682=y
CONFIG_SND_SOC_INTEL_AVS_MACH_SSM4567=y
# end of Intel AVS Machine drivers

CONFIG_SND_SOC_INTEL_MACH=y
CONFIG_SND_SOC_INTEL_USER_FRIENDLY_LONG_NAMES=y
CONFIG_SND_SOC_INTEL_HDA_DSP_COMMON=y
CONFIG_SND_SOC_INTEL_SOF_MAXIM_COMMON=y
CONFIG_SND_SOC_INTEL_SOF_REALTEK_COMMON=y
CONFIG_SND_SOC_INTEL_HASWELL_MACH=y
CONFIG_SND_SOC_INTEL_BDW_RT5650_MACH=y
CONFIG_SND_SOC_INTEL_BDW_RT5677_MACH=y
CONFIG_SND_SOC_INTEL_BROADWELL_MACH=y
CONFIG_SND_SOC_INTEL_BYTCR_RT5640_MACH=y
CONFIG_SND_SOC_INTEL_BYTCR_RT5651_MACH=y
CONFIG_SND_SOC_INTEL_BYTCR_WM5102_MACH=y
CONFIG_SND_SOC_INTEL_CHT_BSW_RT5672_MACH=y
CONFIG_SND_SOC_INTEL_CHT_BSW_RT5645_MACH=y
CONFIG_SND_SOC_INTEL_CHT_BSW_MAX98090_TI_MACH=y
CONFIG_SND_SOC_INTEL_CHT_BSW_NAU8824_MACH=y
CONFIG_SND_SOC_INTEL_BYT_CHT_CX2072X_MACH=y
CONFIG_SND_SOC_INTEL_BYT_CHT_DA7213_MACH=y
CONFIG_SND_SOC_INTEL_BYT_CHT_ES8316_MACH=y
CONFIG_SND_SOC_INTEL_BYT_CHT_NOCODEC_MACH=y
CONFIG_SND_SOC_INTEL_SKL_RT286_MACH=y
CONFIG_SND_SOC_INTEL_SKL_NAU88L25_SSM4567_MACH=y
CONFIG_SND_SOC_INTEL_SKL_NAU88L25_MAX98357A_MACH=y
CONFIG_SND_SOC_INTEL_DA7219_MAX98357A_GENERIC=y
CONFIG_SND_SOC_INTEL_BXT_DA7219_MAX98357A_COMMON=y
CONFIG_SND_SOC_INTEL_BXT_DA7219_MAX98357A_MACH=y
CONFIG_SND_SOC_INTEL_BXT_RT298_MACH=y
CONFIG_SND_SOC_INTEL_SOF_WM8804_MACH=y
CONFIG_SND_SOC_INTEL_KBL_RT5663_MAX98927_MACH=y
CONFIG_SND_SOC_INTEL_KBL_RT5663_RT5514_MAX98927_MACH=y
CONFIG_SND_SOC_INTEL_KBL_DA7219_MAX98357A_MACH=y
CONFIG_SND_SOC_INTEL_KBL_DA7219_MAX98927_MACH=y
CONFIG_SND_SOC_INTEL_KBL_RT5660_MACH=y
CONFIG_SND_SOC_INTEL_SKL_HDA_DSP_GENERIC_MACH=y
CONFIG_SND_SOC_INTEL_SOF_RT5682_MACH=y
CONFIG_SND_SOC_INTEL_SOF_PCM512x_MACH=y
CONFIG_SND_SOC_INTEL_SOUNDWIRE_SOF_MACH=y
CONFIG_SND_SOC_MTK_BTCVSD=y
CONFIG_SND_SOC_SOF_TOPLEVEL=y
CONFIG_SND_SOC_SOF_PCI_DEV=y
CONFIG_SND_SOC_SOF_PCI=y
CONFIG_SND_SOC_SOF_ACPI=y
CONFIG_SND_SOC_SOF_ACPI_DEV=y
CONFIG_SND_SOC_SOF_OF=y
CONFIG_SND_SOC_SOF_DEBUG_PROBES=y
CONFIG_SND_SOC_SOF_CLIENT=y
CONFIG_SND_SOC_SOF_DEVELOPER_SUPPORT=y
CONFIG_SND_SOC_SOF_FORCE_PROBE_WORKQUEUE=y
CONFIG_SND_SOC_SOF_NOCODEC=y
CONFIG_SND_SOC_SOF_NOCODEC_SUPPORT=y
CONFIG_SND_SOC_SOF_STRICT_ABI_CHECKS=y
CONFIG_SND_SOC_SOF_DEBUG=y
CONFIG_SND_SOC_SOF_FORCE_NOCODEC_MODE=y
CONFIG_SND_SOC_SOF_DEBUG_XRUN_STOP=y
CONFIG_SND_SOC_SOF_DEBUG_VERBOSE_IPC=y
CONFIG_SND_SOC_SOF_DEBUG_FORCE_IPC_POSITION=y
CONFIG_SND_SOC_SOF_DEBUG_ENABLE_DEBUGFS_CACHE=y
CONFIG_SND_SOC_SOF_DEBUG_ENABLE_FIRMWARE_TRACE=y
CONFIG_SND_SOC_SOF_DEBUG_IPC_FLOOD_TEST=y
CONFIG_SND_SOC_SOF_DEBUG_IPC_FLOOD_TEST_NUM=2
CONFIG_SND_SOC_SOF_DEBUG_IPC_MSG_INJECTOR=y
CONFIG_SND_SOC_SOF_DEBUG_RETAIN_DSP_CONTEXT=y
CONFIG_SND_SOC_SOF=y
CONFIG_SND_SOC_SOF_PROBE_WORK_QUEUE=y
CONFIG_SND_SOC_SOF_IPC3=y
CONFIG_SND_SOC_SOF_INTEL_IPC4=y
CONFIG_SND_SOC_SOF_AMD_TOPLEVEL=y
CONFIG_SND_SOC_SOF_AMD_COMMON=y
CONFIG_SND_SOC_SOF_AMD_RENOIR=y
CONFIG_SND_SOC_SOF_INTEL_TOPLEVEL=y
CONFIG_SND_SOC_SOF_INTEL_HIFI_EP_IPC=y
CONFIG_SND_SOC_SOF_INTEL_ATOM_HIFI_EP=y
CONFIG_SND_SOC_SOF_INTEL_COMMON=y
CONFIG_SND_SOC_SOF_BAYTRAIL=y
CONFIG_SND_SOC_SOF_BROADWELL=y
CONFIG_SND_SOC_SOF_MERRIFIELD=y
CONFIG_SND_SOC_SOF_INTEL_APL=y
CONFIG_SND_SOC_SOF_APOLLOLAKE=y
CONFIG_SND_SOC_SOF_GEMINILAKE=y
CONFIG_SND_SOC_SOF_INTEL_CNL=y
CONFIG_SND_SOC_SOF_CANNONLAKE=y
CONFIG_SND_SOC_SOF_COFFEELAKE=y
CONFIG_SND_SOC_SOF_COMETLAKE=y
CONFIG_SND_SOC_SOF_INTEL_ICL=y
CONFIG_SND_SOC_SOF_ICELAKE=y
CONFIG_SND_SOC_SOF_JASPERLAKE=y
CONFIG_SND_SOC_SOF_INTEL_TGL=y
CONFIG_SND_SOC_SOF_TIGERLAKE=y
CONFIG_SND_SOC_SOF_ELKHARTLAKE=y
CONFIG_SND_SOC_SOF_ALDERLAKE=y
CONFIG_SND_SOC_SOF_INTEL_MTL=y
CONFIG_SND_SOC_SOF_METEORLAKE=y
CONFIG_SND_SOC_SOF_HDA_COMMON=y
CONFIG_SND_SOC_SOF_HDA_LINK_BASELINE=y
CONFIG_SND_SOC_SOF_HDA_PROBES=y
CONFIG_SND_SOC_SOF_INTEL_SOUNDWIRE_LINK_BASELINE=y
CONFIG_SND_SOC_SOF_INTEL_SOUNDWIRE=y
CONFIG_SND_SOC_SOF_XTENSA=y

#
# STMicroelectronics STM32 SOC audio support
#
# end of STMicroelectronics STM32 SOC audio support

CONFIG_SND_SOC_XILINX_I2S=y
CONFIG_SND_SOC_XILINX_AUDIO_FORMATTER=y
CONFIG_SND_SOC_XILINX_SPDIF=y
CONFIG_SND_SOC_XTFPGA_I2S=y
CONFIG_SND_SOC_I2C_AND_SPI=y

#
# CODEC drivers
#
CONFIG_SND_SOC_ARIZONA=y
CONFIG_SND_SOC_WM_ADSP=y
CONFIG_SND_SOC_AC97_CODEC=y
CONFIG_SND_SOC_ADAU_UTILS=y
CONFIG_SND_SOC_ADAU1372=y
CONFIG_SND_SOC_ADAU1372_I2C=y
CONFIG_SND_SOC_ADAU1372_SPI=y
CONFIG_SND_SOC_ADAU1701=y
CONFIG_SND_SOC_ADAU17X1=y
CONFIG_SND_SOC_ADAU1761=y
CONFIG_SND_SOC_ADAU1761_I2C=y
CONFIG_SND_SOC_ADAU1761_SPI=y
CONFIG_SND_SOC_ADAU7002=y
CONFIG_SND_SOC_ADAU7118=y
CONFIG_SND_SOC_ADAU7118_HW=y
CONFIG_SND_SOC_ADAU7118_I2C=y
CONFIG_SND_SOC_AK4104=y
CONFIG_SND_SOC_AK4118=y
CONFIG_SND_SOC_AK4375=y
CONFIG_SND_SOC_AK4458=y
CONFIG_SND_SOC_AK4554=y
CONFIG_SND_SOC_AK4613=y
CONFIG_SND_SOC_AK4642=y
CONFIG_SND_SOC_AK5386=y
CONFIG_SND_SOC_AK5558=y
CONFIG_SND_SOC_ALC5623=y
CONFIG_SND_SOC_AW8738=y
CONFIG_SND_SOC_BD28623=y
CONFIG_SND_SOC_BT_SCO=y
CONFIG_SND_SOC_CPCAP=y
CONFIG_SND_SOC_CROS_EC_CODEC=y
CONFIG_SND_SOC_CS35L32=y
CONFIG_SND_SOC_CS35L33=y
CONFIG_SND_SOC_CS35L34=y
CONFIG_SND_SOC_CS35L35=y
CONFIG_SND_SOC_CS35L36=y
CONFIG_SND_SOC_CS35L41_LIB=y
CONFIG_SND_SOC_CS35L41=y
CONFIG_SND_SOC_CS35L41_SPI=y
CONFIG_SND_SOC_CS35L41_I2C=y
CONFIG_SND_SOC_CS35L45_TABLES=y
CONFIG_SND_SOC_CS35L45=y
CONFIG_SND_SOC_CS35L45_SPI=y
CONFIG_SND_SOC_CS35L45_I2C=y
CONFIG_SND_SOC_CS42L42=y
CONFIG_SND_SOC_CS42L51=y
CONFIG_SND_SOC_CS42L51_I2C=y
CONFIG_SND_SOC_CS42L52=y
CONFIG_SND_SOC_CS42L56=y
CONFIG_SND_SOC_CS42L73=y
CONFIG_SND_SOC_CS4234=y
CONFIG_SND_SOC_CS4265=y
CONFIG_SND_SOC_CS4270=y
CONFIG_SND_SOC_CS4271=y
CONFIG_SND_SOC_CS4271_I2C=y
CONFIG_SND_SOC_CS4271_SPI=y
CONFIG_SND_SOC_CS42XX8=y
CONFIG_SND_SOC_CS42XX8_I2C=y
CONFIG_SND_SOC_CS43130=y
CONFIG_SND_SOC_CS4341=y
CONFIG_SND_SOC_CS4349=y
CONFIG_SND_SOC_CS53L30=y
CONFIG_SND_SOC_CX2072X=y
CONFIG_SND_SOC_DA7213=y
CONFIG_SND_SOC_DA7219=y
CONFIG_SND_SOC_DMIC=y
CONFIG_SND_SOC_HDMI_CODEC=y
CONFIG_SND_SOC_ES7134=y
CONFIG_SND_SOC_ES7241=y
CONFIG_SND_SOC_ES8316=y
CONFIG_SND_SOC_ES8328=y
CONFIG_SND_SOC_ES8328_I2C=y
CONFIG_SND_SOC_ES8328_SPI=y
CONFIG_SND_SOC_GTM601=y
CONFIG_SND_SOC_HDAC_HDMI=y
CONFIG_SND_SOC_HDAC_HDA=y
CONFIG_SND_SOC_HDA=y
CONFIG_SND_SOC_ICS43432=y
CONFIG_SND_SOC_INNO_RK3036=y
CONFIG_SND_SOC_LOCHNAGAR_SC=y
CONFIG_SND_SOC_MAX98088=y
CONFIG_SND_SOC_MAX98090=y
CONFIG_SND_SOC_MAX98357A=y
CONFIG_SND_SOC_MAX98504=y
CONFIG_SND_SOC_MAX9867=y
CONFIG_SND_SOC_MAX98927=y
CONFIG_SND_SOC_MAX98520=y
CONFIG_SND_SOC_MAX98373=y
CONFIG_SND_SOC_MAX98373_I2C=y
CONFIG_SND_SOC_MAX98373_SDW=y
CONFIG_SND_SOC_MAX98390=y
CONFIG_SND_SOC_MAX98396=y
CONFIG_SND_SOC_MAX9860=y
CONFIG_SND_SOC_MSM8916_WCD_ANALOG=y
CONFIG_SND_SOC_MSM8916_WCD_DIGITAL=y
CONFIG_SND_SOC_PCM1681=y
CONFIG_SND_SOC_PCM1789=y
CONFIG_SND_SOC_PCM1789_I2C=y
CONFIG_SND_SOC_PCM179X=y
CONFIG_SND_SOC_PCM179X_I2C=y
CONFIG_SND_SOC_PCM179X_SPI=y
CONFIG_SND_SOC_PCM186X=y
CONFIG_SND_SOC_PCM186X_I2C=y
CONFIG_SND_SOC_PCM186X_SPI=y
CONFIG_SND_SOC_PCM3060=y
CONFIG_SND_SOC_PCM3060_I2C=y
CONFIG_SND_SOC_PCM3060_SPI=y
CONFIG_SND_SOC_PCM3168A=y
CONFIG_SND_SOC_PCM3168A_I2C=y
CONFIG_SND_SOC_PCM3168A_SPI=y
CONFIG_SND_SOC_PCM5102A=y
CONFIG_SND_SOC_PCM512x=y
CONFIG_SND_SOC_PCM512x_I2C=y
CONFIG_SND_SOC_PCM512x_SPI=y
CONFIG_SND_SOC_RK3328=y
CONFIG_SND_SOC_RK817=y
CONFIG_SND_SOC_RL6231=y
CONFIG_SND_SOC_RL6347A=y
CONFIG_SND_SOC_RT274=y
CONFIG_SND_SOC_RT286=y
CONFIG_SND_SOC_RT298=y
CONFIG_SND_SOC_RT1011=y
CONFIG_SND_SOC_RT1015=y
CONFIG_SND_SOC_RT1015P=y
CONFIG_SND_SOC_RT1019=y
CONFIG_SND_SOC_RT1308=y
CONFIG_SND_SOC_RT1308_SDW=y
CONFIG_SND_SOC_RT1316_SDW=y
CONFIG_SND_SOC_RT5514=y
CONFIG_SND_SOC_RT5514_SPI=y
CONFIG_SND_SOC_RT5616=y
CONFIG_SND_SOC_RT5631=y
CONFIG_SND_SOC_RT5640=y
CONFIG_SND_SOC_RT5645=y
CONFIG_SND_SOC_RT5651=y
CONFIG_SND_SOC_RT5659=y
CONFIG_SND_SOC_RT5660=y
CONFIG_SND_SOC_RT5663=y
CONFIG_SND_SOC_RT5670=y
CONFIG_SND_SOC_RT5677=y
CONFIG_SND_SOC_RT5677_SPI=y
CONFIG_SND_SOC_RT5682=y
CONFIG_SND_SOC_RT5682_I2C=y
CONFIG_SND_SOC_RT5682_SDW=y
CONFIG_SND_SOC_RT5682S=y
CONFIG_SND_SOC_RT700=y
CONFIG_SND_SOC_RT700_SDW=y
CONFIG_SND_SOC_RT711=y
CONFIG_SND_SOC_RT711_SDW=y
CONFIG_SND_SOC_RT711_SDCA_SDW=y
CONFIG_SND_SOC_RT715=y
CONFIG_SND_SOC_RT715_SDW=y
CONFIG_SND_SOC_RT715_SDCA_SDW=y
CONFIG_SND_SOC_RT9120=y
CONFIG_SND_SOC_SDW_MOCKUP=y
CONFIG_SND_SOC_SGTL5000=y
CONFIG_SND_SOC_SI476X=y
CONFIG_SND_SOC_SIGMADSP=y
CONFIG_SND_SOC_SIGMADSP_I2C=y
CONFIG_SND_SOC_SIGMADSP_REGMAP=y
CONFIG_SND_SOC_SIMPLE_AMPLIFIER=y
CONFIG_SND_SOC_SIMPLE_MUX=y
CONFIG_SND_SOC_SPDIF=y
CONFIG_SND_SOC_SSM2305=y
CONFIG_SND_SOC_SSM2518=y
CONFIG_SND_SOC_SSM2602=y
CONFIG_SND_SOC_SSM2602_SPI=y
CONFIG_SND_SOC_SSM2602_I2C=y
CONFIG_SND_SOC_SSM4567=y
CONFIG_SND_SOC_STA32X=y
CONFIG_SND_SOC_STA350=y
CONFIG_SND_SOC_STI_SAS=y
CONFIG_SND_SOC_TAS2552=y
CONFIG_SND_SOC_TAS2562=y
CONFIG_SND_SOC_TAS2764=y
CONFIG_SND_SOC_TAS2770=y
CONFIG_SND_SOC_TAS2780=y
CONFIG_SND_SOC_TAS5086=y
CONFIG_SND_SOC_TAS571X=y
CONFIG_SND_SOC_TAS5720=y
CONFIG_SND_SOC_TAS5805M=y
CONFIG_SND_SOC_TAS6424=y
CONFIG_SND_SOC_TDA7419=y
CONFIG_SND_SOC_TFA9879=y
CONFIG_SND_SOC_TFA989X=y
CONFIG_SND_SOC_TLV320ADC3XXX=y
CONFIG_SND_SOC_TLV320AIC23=y
CONFIG_SND_SOC_TLV320AIC23_I2C=y
CONFIG_SND_SOC_TLV320AIC23_SPI=y
CONFIG_SND_SOC_TLV320AIC31XX=y
CONFIG_SND_SOC_TLV320AIC32X4=y
CONFIG_SND_SOC_TLV320AIC32X4_I2C=y
CONFIG_SND_SOC_TLV320AIC32X4_SPI=y
CONFIG_SND_SOC_TLV320AIC3X=y
CONFIG_SND_SOC_TLV320AIC3X_I2C=y
CONFIG_SND_SOC_TLV320AIC3X_SPI=y
CONFIG_SND_SOC_TLV320ADCX140=y
CONFIG_SND_SOC_TS3A227E=y
CONFIG_SND_SOC_TSCS42XX=y
CONFIG_SND_SOC_TSCS454=y
CONFIG_SND_SOC_UDA1334=y
CONFIG_SND_SOC_WCD9335=y
CONFIG_SND_SOC_WCD_MBHC=y
CONFIG_SND_SOC_WCD934X=y
CONFIG_SND_SOC_WCD938X=y
CONFIG_SND_SOC_WCD938X_SDW=y
CONFIG_SND_SOC_WM5102=y
CONFIG_SND_SOC_WM8510=y
CONFIG_SND_SOC_WM8523=y
CONFIG_SND_SOC_WM8524=y
CONFIG_SND_SOC_WM8580=y
CONFIG_SND_SOC_WM8711=y
CONFIG_SND_SOC_WM8728=y
CONFIG_SND_SOC_WM8731=y
CONFIG_SND_SOC_WM8731_I2C=y
CONFIG_SND_SOC_WM8731_SPI=y
CONFIG_SND_SOC_WM8737=y
CONFIG_SND_SOC_WM8741=y
CONFIG_SND_SOC_WM8750=y
CONFIG_SND_SOC_WM8753=y
CONFIG_SND_SOC_WM8770=y
CONFIG_SND_SOC_WM8776=y
CONFIG_SND_SOC_WM8782=y
CONFIG_SND_SOC_WM8804=y
CONFIG_SND_SOC_WM8804_I2C=y
CONFIG_SND_SOC_WM8804_SPI=y
CONFIG_SND_SOC_WM8903=y
CONFIG_SND_SOC_WM8904=y
CONFIG_SND_SOC_WM8940=y
CONFIG_SND_SOC_WM8960=y
CONFIG_SND_SOC_WM8962=y
CONFIG_SND_SOC_WM8974=y
CONFIG_SND_SOC_WM8978=y
CONFIG_SND_SOC_WM8985=y
CONFIG_SND_SOC_WSA881X=y
CONFIG_SND_SOC_WSA883X=y
CONFIG_SND_SOC_ZL38060=y
CONFIG_SND_SOC_MAX9759=y
CONFIG_SND_SOC_MT6351=y
CONFIG_SND_SOC_MT6358=y
CONFIG_SND_SOC_MT6660=y
CONFIG_SND_SOC_NAU8315=y
CONFIG_SND_SOC_NAU8540=y
CONFIG_SND_SOC_NAU8810=y
CONFIG_SND_SOC_NAU8821=y
CONFIG_SND_SOC_NAU8822=y
CONFIG_SND_SOC_NAU8824=y
CONFIG_SND_SOC_NAU8825=y
CONFIG_SND_SOC_TPA6130A2=y
CONFIG_SND_SOC_LPASS_MACRO_COMMON=y
CONFIG_SND_SOC_LPASS_WSA_MACRO=y
CONFIG_SND_SOC_LPASS_VA_MACRO=y
CONFIG_SND_SOC_LPASS_RX_MACRO=y
CONFIG_SND_SOC_LPASS_TX_MACRO=y
# end of CODEC drivers

CONFIG_SND_SIMPLE_CARD_UTILS=y
CONFIG_SND_SIMPLE_CARD=y
CONFIG_SND_AUDIO_GRAPH_CARD=y
CONFIG_SND_AUDIO_GRAPH_CARD2=y
CONFIG_SND_AUDIO_GRAPH_CARD2_CUSTOM_SAMPLE=y
CONFIG_SND_TEST_COMPONENT=y
CONFIG_SND_X86=y
CONFIG_HDMI_LPE_AUDIO=y
CONFIG_SND_SYNTH_EMUX=y
CONFIG_SND_XEN_FRONTEND=y
CONFIG_SND_VIRTIO=y
CONFIG_AC97_BUS=y

#
# HID support
#
CONFIG_HID=y
CONFIG_HID_BATTERY_STRENGTH=y
CONFIG_HIDRAW=y
CONFIG_UHID=y
CONFIG_HID_GENERIC=y

#
# Special HID drivers
#
CONFIG_HID_A4TECH=y
CONFIG_HID_ACCUTOUCH=y
CONFIG_HID_ACRUX=y
CONFIG_HID_ACRUX_FF=y
CONFIG_HID_APPLE=y
CONFIG_HID_APPLEIR=y
CONFIG_HID_ASUS=y
CONFIG_HID_AUREAL=y
CONFIG_HID_BELKIN=y
CONFIG_HID_BETOP_FF=y
CONFIG_HID_BIGBEN_FF=y
CONFIG_HID_CHERRY=y
CONFIG_HID_CHICONY=y
CONFIG_HID_CORSAIR=y
CONFIG_HID_COUGAR=y
CONFIG_HID_MACALLY=y
CONFIG_HID_PRODIKEYS=y
CONFIG_HID_CMEDIA=y
CONFIG_HID_CP2112=y
CONFIG_HID_CREATIVE_SB0540=y
CONFIG_HID_CYPRESS=y
CONFIG_HID_DRAGONRISE=y
CONFIG_DRAGONRISE_FF=y
CONFIG_HID_EMS_FF=y
CONFIG_HID_ELAN=y
CONFIG_HID_ELECOM=y
CONFIG_HID_ELO=y
CONFIG_HID_EZKEY=y
CONFIG_HID_FT260=y
CONFIG_HID_GEMBIRD=y
CONFIG_HID_GFRM=y
CONFIG_HID_GLORIOUS=y
CONFIG_HID_HOLTEK=y
CONFIG_HOLTEK_FF=y
CONFIG_HID_VIVALDI_COMMON=y
CONFIG_HID_GOOGLE_HAMMER=y
CONFIG_HID_VIVALDI=y
CONFIG_HID_GT683R=y
CONFIG_HID_KEYTOUCH=y
CONFIG_HID_KYE=y
CONFIG_HID_UCLOGIC=y
CONFIG_HID_WALTOP=y
CONFIG_HID_VIEWSONIC=y
CONFIG_HID_XIAOMI=y
CONFIG_HID_GYRATION=y
CONFIG_HID_ICADE=y
CONFIG_HID_ITE=y
CONFIG_HID_JABRA=y
CONFIG_HID_TWINHAN=y
CONFIG_HID_KENSINGTON=y
CONFIG_HID_LCPOWER=y
CONFIG_HID_LED=y
CONFIG_HID_LENOVO=y
CONFIG_HID_LETSKETCH=y
CONFIG_HID_LOGITECH=y
CONFIG_HID_LOGITECH_DJ=y
CONFIG_HID_LOGITECH_HIDPP=y
CONFIG_LOGITECH_FF=y
CONFIG_LOGIRUMBLEPAD2_FF=y
CONFIG_LOGIG940_FF=y
CONFIG_LOGIWHEELS_FF=y
CONFIG_HID_MAGICMOUSE=y
CONFIG_HID_MALTRON=y
CONFIG_HID_MAYFLASH=y
CONFIG_HID_MEGAWORLD_FF=y
CONFIG_HID_REDRAGON=y
CONFIG_HID_MICROSOFT=y
CONFIG_HID_MONTEREY=y
CONFIG_HID_MULTITOUCH=y
CONFIG_HID_NINTENDO=y
CONFIG_NINTENDO_FF=y
CONFIG_HID_NTI=y
CONFIG_HID_NTRIG=y
CONFIG_HID_ORTEK=y
CONFIG_HID_PANTHERLORD=y
CONFIG_PANTHERLORD_FF=y
CONFIG_HID_PENMOUNT=y
CONFIG_HID_PETALYNX=y
CONFIG_HID_PICOLCD=y
CONFIG_HID_PICOLCD_FB=y
CONFIG_HID_PICOLCD_BACKLIGHT=y
CONFIG_HID_PICOLCD_LCD=y
CONFIG_HID_PICOLCD_LEDS=y
CONFIG_HID_PICOLCD_CIR=y
CONFIG_HID_PLANTRONICS=y
CONFIG_HID_PLAYSTATION=y
CONFIG_PLAYSTATION_FF=y
CONFIG_HID_RAZER=y
CONFIG_HID_PRIMAX=y
CONFIG_HID_RETRODE=y
CONFIG_HID_ROCCAT=y
CONFIG_HID_SAITEK=y
CONFIG_HID_SAMSUNG=y
CONFIG_HID_SEMITEK=y
CONFIG_HID_SIGMAMICRO=y
CONFIG_HID_SONY=y
CONFIG_SONY_FF=y
CONFIG_HID_SPEEDLINK=y
CONFIG_HID_STEAM=y
CONFIG_HID_STEELSERIES=y
CONFIG_HID_SUNPLUS=y
CONFIG_HID_RMI=y
CONFIG_HID_GREENASIA=y
CONFIG_GREENASIA_FF=y
CONFIG_HID_HYPERV_MOUSE=y
CONFIG_HID_SMARTJOYPLUS=y
CONFIG_SMARTJOYPLUS_FF=y
CONFIG_HID_TIVO=y
CONFIG_HID_TOPSEED=y
CONFIG_HID_THINGM=y
CONFIG_HID_THRUSTMASTER=y
CONFIG_THRUSTMASTER_FF=y
CONFIG_HID_UDRAW_PS3=y
CONFIG_HID_U2FZERO=y
CONFIG_HID_WACOM=y
CONFIG_HID_WIIMOTE=y
CONFIG_HID_XINMO=y
CONFIG_HID_ZEROPLUS=y
CONFIG_ZEROPLUS_FF=y
CONFIG_HID_ZYDACRON=y
CONFIG_HID_SENSOR_HUB=y
CONFIG_HID_SENSOR_CUSTOM_SENSOR=y
CONFIG_HID_ALPS=y
CONFIG_HID_MCP2221=y
CONFIG_HID_KUNIT_TEST=y
# end of Special HID drivers

#
# USB HID support
#
CONFIG_USB_HID=y
CONFIG_HID_PID=y
CONFIG_USB_HIDDEV=y
# end of USB HID support

#
# I2C HID support
#
CONFIG_I2C_HID_ACPI=y
CONFIG_I2C_HID_OF=y
CONFIG_I2C_HID_OF_ELAN=y
CONFIG_I2C_HID_OF_GOODIX=y
# end of I2C HID support

CONFIG_I2C_HID_CORE=y

#
# Intel ISH HID support
#
CONFIG_INTEL_ISH_HID=y
CONFIG_INTEL_ISH_FIRMWARE_DOWNLOADER=y
# end of Intel ISH HID support

#
# AMD SFH HID Support
#
CONFIG_AMD_SFH_HID=y
# end of AMD SFH HID Support

#
# Surface System Aggregator Module HID support
#
CONFIG_SURFACE_HID=y
CONFIG_SURFACE_KBD=y
# end of Surface System Aggregator Module HID support

CONFIG_SURFACE_HID_CORE=y
# end of HID support

CONFIG_USB_OHCI_LITTLE_ENDIAN=y
CONFIG_USB_SUPPORT=y
CONFIG_USB_COMMON=y
CONFIG_USB_LED_TRIG=y
CONFIG_USB_ULPI_BUS=y
CONFIG_USB_CONN_GPIO=y
CONFIG_USB_ARCH_HAS_HCD=y
CONFIG_USB=y
CONFIG_USB_PCI=y
CONFIG_USB_ANNOUNCE_NEW_DEVICES=y

#
# Miscellaneous USB options
#
CONFIG_USB_DEFAULT_PERSIST=y
CONFIG_USB_FEW_INIT_RETRIES=y
CONFIG_USB_DYNAMIC_MINORS=y
CONFIG_USB_OTG=y
CONFIG_USB_OTG_PRODUCTLIST=y
CONFIG_USB_OTG_DISABLE_EXTERNAL_HUB=y
CONFIG_USB_OTG_FSM=y
CONFIG_USB_LEDS_TRIGGER_USBPORT=y
CONFIG_USB_AUTOSUSPEND_DELAY=2
CONFIG_USB_MON=y

#
# USB Host Controller Drivers
#
CONFIG_USB_C67X00_HCD=y
CONFIG_USB_XHCI_HCD=y
CONFIG_USB_XHCI_DBGCAP=y
CONFIG_USB_XHCI_PCI=y
CONFIG_USB_XHCI_PCI_RENESAS=y
CONFIG_USB_XHCI_PLATFORM=y
CONFIG_USB_EHCI_HCD=y
CONFIG_USB_EHCI_ROOT_HUB_TT=y
CONFIG_USB_EHCI_TT_NEWSCHED=y
CONFIG_USB_EHCI_PCI=y
CONFIG_USB_EHCI_FSL=y
CONFIG_USB_EHCI_HCD_PLATFORM=y
CONFIG_USB_OXU210HP_HCD=y
CONFIG_USB_ISP116X_HCD=y
CONFIG_USB_FOTG210_HCD=y
CONFIG_USB_MAX3421_HCD=y
CONFIG_USB_OHCI_HCD=y
CONFIG_USB_OHCI_HCD_PCI=y
CONFIG_USB_OHCI_HCD_SSB=y
CONFIG_USB_OHCI_HCD_PLATFORM=y
CONFIG_USB_UHCI_HCD=y
CONFIG_USB_U132_HCD=y
CONFIG_USB_SL811_HCD=y
CONFIG_USB_SL811_HCD_ISO=y
CONFIG_USB_SL811_CS=y
CONFIG_USB_R8A66597_HCD=y
CONFIG_USB_HCD_BCMA=y
CONFIG_USB_HCD_SSB=y
CONFIG_USB_HCD_TEST_MODE=y
CONFIG_USB_XEN_HCD=y

#
# USB Device Class drivers
#
CONFIG_USB_ACM=y
CONFIG_USB_PRINTER=y
CONFIG_USB_WDM=y
CONFIG_USB_TMC=y

#
# NOTE: USB_STORAGE depends on SCSI but BLK_DEV_SD may
#

#
# also be needed; see USB_STORAGE Help for more info
#
CONFIG_USB_STORAGE=y
CONFIG_USB_STORAGE_DEBUG=y
CONFIG_USB_STORAGE_REALTEK=y
CONFIG_REALTEK_AUTOPM=y
CONFIG_USB_STORAGE_DATAFAB=y
CONFIG_USB_STORAGE_FREECOM=y
CONFIG_USB_STORAGE_ISD200=y
CONFIG_USB_STORAGE_USBAT=y
CONFIG_USB_STORAGE_SDDR09=y
CONFIG_USB_STORAGE_SDDR55=y
CONFIG_USB_STORAGE_JUMPSHOT=y
CONFIG_USB_STORAGE_ALAUDA=y
CONFIG_USB_STORAGE_ONETOUCH=y
CONFIG_USB_STORAGE_KARMA=y
CONFIG_USB_STORAGE_CYPRESS_ATACB=y
CONFIG_USB_STORAGE_ENE_UB6250=y
CONFIG_USB_UAS=y

#
# USB Imaging devices
#
CONFIG_USB_MDC800=y
CONFIG_USB_MICROTEK=y
CONFIG_USBIP_CORE=y
CONFIG_USBIP_VHCI_HCD=y
CONFIG_USBIP_VHCI_HC_PORTS=8
CONFIG_USBIP_VHCI_NR_HCS=1
CONFIG_USBIP_HOST=y
CONFIG_USBIP_VUDC=y
CONFIG_USBIP_DEBUG=y
CONFIG_USB_CDNS_SUPPORT=y
CONFIG_USB_CDNS_HOST=y
CONFIG_USB_CDNS3=y
CONFIG_USB_CDNS3_GADGET=y
CONFIG_USB_CDNS3_HOST=y
CONFIG_USB_CDNS3_PCI_WRAP=y
CONFIG_USB_CDNSP_PCI=y
CONFIG_USB_CDNSP_GADGET=y
CONFIG_USB_CDNSP_HOST=y
CONFIG_USB_MUSB_HDRC=y
# CONFIG_USB_MUSB_HOST is not set
# CONFIG_USB_MUSB_GADGET is not set
CONFIG_USB_MUSB_DUAL_ROLE=y

#
# Platform Glue Layer
#

#
# MUSB DMA mode
#
CONFIG_MUSB_PIO_ONLY=y
CONFIG_USB_DWC3=y
CONFIG_USB_DWC3_ULPI=y
# CONFIG_USB_DWC3_HOST is not set
# CONFIG_USB_DWC3_GADGET is not set
CONFIG_USB_DWC3_DUAL_ROLE=y

#
# Platform Glue Driver Support
#
CONFIG_USB_DWC3_PCI=y
CONFIG_USB_DWC3_HAPS=y
CONFIG_USB_DWC3_OF_SIMPLE=y
CONFIG_USB_DWC2=y
# CONFIG_USB_DWC2_HOST is not set

#
# Gadget/Dual-role mode requires USB Gadget support to be enabled
#
# CONFIG_USB_DWC2_PERIPHERAL is not set
CONFIG_USB_DWC2_DUAL_ROLE=y
CONFIG_USB_DWC2_PCI=y
CONFIG_USB_DWC2_DEBUG=y
CONFIG_USB_DWC2_VERBOSE=y
CONFIG_USB_DWC2_TRACK_MISSED_SOFS=y
CONFIG_USB_DWC2_DEBUG_PERIODIC=y
CONFIG_USB_CHIPIDEA=y
CONFIG_USB_CHIPIDEA_UDC=y
CONFIG_USB_CHIPIDEA_HOST=y
CONFIG_USB_CHIPIDEA_PCI=y
CONFIG_USB_CHIPIDEA_MSM=y
CONFIG_USB_CHIPIDEA_IMX=y
CONFIG_USB_CHIPIDEA_GENERIC=y
CONFIG_USB_CHIPIDEA_TEGRA=y
CONFIG_USB_ISP1760=y
CONFIG_USB_ISP1760_HCD=y
CONFIG_USB_ISP1761_UDC=y
# CONFIG_USB_ISP1760_HOST_ROLE is not set
# CONFIG_USB_ISP1760_GADGET_ROLE is not set
CONFIG_USB_ISP1760_DUAL_ROLE=y

#
# USB port drivers
#
CONFIG_USB_USS720=y
CONFIG_USB_SERIAL=y
CONFIG_USB_SERIAL_CONSOLE=y
CONFIG_USB_SERIAL_GENERIC=y
CONFIG_USB_SERIAL_SIMPLE=y
CONFIG_USB_SERIAL_AIRCABLE=y
CONFIG_USB_SERIAL_ARK3116=y
CONFIG_USB_SERIAL_BELKIN=y
CONFIG_USB_SERIAL_CH341=y
CONFIG_USB_SERIAL_WHITEHEAT=y
CONFIG_USB_SERIAL_DIGI_ACCELEPORT=y
CONFIG_USB_SERIAL_CP210X=y
CONFIG_USB_SERIAL_CYPRESS_M8=y
CONFIG_USB_SERIAL_EMPEG=y
CONFIG_USB_SERIAL_FTDI_SIO=y
CONFIG_USB_SERIAL_VISOR=y
CONFIG_USB_SERIAL_IPAQ=y
CONFIG_USB_SERIAL_IR=y
CONFIG_USB_SERIAL_EDGEPORT=y
CONFIG_USB_SERIAL_EDGEPORT_TI=y
CONFIG_USB_SERIAL_F81232=y
CONFIG_USB_SERIAL_F8153X=y
CONFIG_USB_SERIAL_GARMIN=y
CONFIG_USB_SERIAL_IPW=y
CONFIG_USB_SERIAL_IUU=y
CONFIG_USB_SERIAL_KEYSPAN_PDA=y
CONFIG_USB_SERIAL_KEYSPAN=y
CONFIG_USB_SERIAL_KLSI=y
CONFIG_USB_SERIAL_KOBIL_SCT=y
CONFIG_USB_SERIAL_MCT_U232=y
CONFIG_USB_SERIAL_METRO=y
CONFIG_USB_SERIAL_MOS7720=y
CONFIG_USB_SERIAL_MOS7715_PARPORT=y
CONFIG_USB_SERIAL_MOS7840=y
CONFIG_USB_SERIAL_MXUPORT=y
CONFIG_USB_SERIAL_NAVMAN=y
CONFIG_USB_SERIAL_PL2303=y
CONFIG_USB_SERIAL_OTI6858=y
CONFIG_USB_SERIAL_QCAUX=y
CONFIG_USB_SERIAL_QUALCOMM=y
CONFIG_USB_SERIAL_SPCP8X5=y
CONFIG_USB_SERIAL_SAFE=y
CONFIG_USB_SERIAL_SAFE_PADDED=y
CONFIG_USB_SERIAL_SIERRAWIRELESS=y
CONFIG_USB_SERIAL_SYMBOL=y
CONFIG_USB_SERIAL_TI=y
CONFIG_USB_SERIAL_CYBERJACK=y
CONFIG_USB_SERIAL_WWAN=y
CONFIG_USB_SERIAL_OPTION=y
CONFIG_USB_SERIAL_OMNINET=y
CONFIG_USB_SERIAL_OPTICON=y
CONFIG_USB_SERIAL_XSENS_MT=y
CONFIG_USB_SERIAL_WISHBONE=y
CONFIG_USB_SERIAL_SSU100=y
CONFIG_USB_SERIAL_QT2=y
CONFIG_USB_SERIAL_UPD78F0730=y
CONFIG_USB_SERIAL_XR=y
CONFIG_USB_SERIAL_DEBUG=y

#
# USB Miscellaneous drivers
#
CONFIG_USB_EMI62=y
CONFIG_USB_EMI26=y
CONFIG_USB_ADUTUX=y
CONFIG_USB_SEVSEG=y
CONFIG_USB_LEGOTOWER=y
CONFIG_USB_LCD=y
CONFIG_USB_CYPRESS_CY7C63=y
CONFIG_USB_CYTHERM=y
CONFIG_USB_IDMOUSE=y
CONFIG_USB_FTDI_ELAN=y
CONFIG_USB_APPLEDISPLAY=y
CONFIG_APPLE_MFI_FASTCHARGE=y
CONFIG_USB_SISUSBVGA=y
CONFIG_USB_LD=y
CONFIG_USB_TRANCEVIBRATOR=y
CONFIG_USB_IOWARRIOR=y
CONFIG_USB_TEST=y
CONFIG_USB_EHSET_TEST_FIXTURE=y
CONFIG_USB_ISIGHTFW=y
CONFIG_USB_YUREX=y
CONFIG_USB_EZUSB_FX2=y
CONFIG_USB_HUB_USB251XB=y
CONFIG_USB_HSIC_USB3503=y
CONFIG_USB_HSIC_USB4604=y
CONFIG_USB_LINK_LAYER_TEST=y
CONFIG_USB_CHAOSKEY=y
CONFIG_USB_ONBOARD_HUB=y
CONFIG_USB_ATM=y
CONFIG_USB_SPEEDTOUCH=y
CONFIG_USB_CXACRU=y
CONFIG_USB_UEAGLEATM=y
CONFIG_USB_XUSBATM=y

#
# USB Physical Layer drivers
#
CONFIG_USB_PHY=y
CONFIG_NOP_USB_XCEIV=y
CONFIG_USB_GPIO_VBUS=y
CONFIG_TAHVO_USB=y
CONFIG_TAHVO_USB_HOST_BY_DEFAULT=y
CONFIG_USB_ISP1301=y
# end of USB Physical Layer drivers

CONFIG_USB_GADGET=y
CONFIG_USB_GADGET_DEBUG=y
CONFIG_USB_GADGET_VERBOSE=y
CONFIG_USB_GADGET_DEBUG_FILES=y
CONFIG_USB_GADGET_DEBUG_FS=y
CONFIG_USB_GADGET_VBUS_DRAW=2
CONFIG_USB_GADGET_STORAGE_NUM_BUFFERS=2
CONFIG_U_SERIAL_CONSOLE=y

#
# USB Peripheral Controller
#
CONFIG_USB_FOTG210_UDC=y
CONFIG_USB_GR_UDC=y
CONFIG_USB_R8A66597=y
CONFIG_USB_PXA27X=y
CONFIG_USB_MV_UDC=y
CONFIG_USB_MV_U3D=y
CONFIG_USB_SNP_CORE=y
CONFIG_USB_SNP_UDC_PLAT=y
CONFIG_USB_M66592=y
CONFIG_USB_BDC_UDC=y
CONFIG_USB_AMD5536UDC=y
CONFIG_USB_NET2272=y
CONFIG_USB_NET2272_DMA=y
CONFIG_USB_NET2280=y
CONFIG_USB_GOKU=y
CONFIG_USB_EG20T=y
CONFIG_USB_GADGET_XILINX=y
CONFIG_USB_MAX3420_UDC=y
CONFIG_USB_DUMMY_HCD=y
# end of USB Peripheral Controller

CONFIG_USB_LIBCOMPOSITE=y
CONFIG_USB_F_ACM=y
CONFIG_USB_F_SS_LB=y
CONFIG_USB_U_SERIAL=y
CONFIG_USB_U_ETHER=y
CONFIG_USB_U_AUDIO=y
CONFIG_USB_F_SERIAL=y
CONFIG_USB_F_OBEX=y
CONFIG_USB_F_NCM=y
CONFIG_USB_F_ECM=y
CONFIG_USB_F_PHONET=y
CONFIG_USB_F_EEM=y
CONFIG_USB_F_SUBSET=y
CONFIG_USB_F_RNDIS=y
CONFIG_USB_F_MASS_STORAGE=y
CONFIG_USB_F_FS=y
CONFIG_USB_F_UAC1=y
CONFIG_USB_F_UAC1_LEGACY=y
CONFIG_USB_F_UAC2=y
CONFIG_USB_F_UVC=y
CONFIG_USB_F_MIDI=y
CONFIG_USB_F_HID=y
CONFIG_USB_F_PRINTER=y
CONFIG_USB_F_TCM=y
CONFIG_USB_CONFIGFS=y
CONFIG_USB_CONFIGFS_SERIAL=y
CONFIG_USB_CONFIGFS_ACM=y
CONFIG_USB_CONFIGFS_OBEX=y
CONFIG_USB_CONFIGFS_NCM=y
CONFIG_USB_CONFIGFS_ECM=y
CONFIG_USB_CONFIGFS_ECM_SUBSET=y
CONFIG_USB_CONFIGFS_RNDIS=y
CONFIG_USB_CONFIGFS_EEM=y
CONFIG_USB_CONFIGFS_PHONET=y
CONFIG_USB_CONFIGFS_MASS_STORAGE=y
CONFIG_USB_CONFIGFS_F_LB_SS=y
CONFIG_USB_CONFIGFS_F_FS=y
CONFIG_USB_CONFIGFS_F_UAC1=y
CONFIG_USB_CONFIGFS_F_UAC1_LEGACY=y
CONFIG_USB_CONFIGFS_F_UAC2=y
CONFIG_USB_CONFIGFS_F_MIDI=y
CONFIG_USB_CONFIGFS_F_HID=y
CONFIG_USB_CONFIGFS_F_UVC=y
CONFIG_USB_CONFIGFS_F_PRINTER=y
CONFIG_USB_CONFIGFS_F_TCM=y

#
# USB Gadget precomposed configurations
#
CONFIG_USB_ZERO=y
CONFIG_USB_ZERO_HNPTEST=y
CONFIG_USB_AUDIO=y
CONFIG_GADGET_UAC1=y
CONFIG_GADGET_UAC1_LEGACY=y
CONFIG_USB_ETH=y
CONFIG_USB_ETH_RNDIS=y
CONFIG_USB_ETH_EEM=y
CONFIG_USB_G_NCM=y
CONFIG_USB_GADGETFS=y
CONFIG_USB_FUNCTIONFS=y
CONFIG_USB_FUNCTIONFS_ETH=y
CONFIG_USB_FUNCTIONFS_RNDIS=y
CONFIG_USB_FUNCTIONFS_GENERIC=y
CONFIG_USB_MASS_STORAGE=y
CONFIG_USB_GADGET_TARGET=y
CONFIG_USB_G_SERIAL=y
CONFIG_USB_MIDI_GADGET=y
CONFIG_USB_G_PRINTER=y
CONFIG_USB_CDC_COMPOSITE=y
CONFIG_USB_G_NOKIA=y
CONFIG_USB_G_ACM_MS=y
CONFIG_USB_G_MULTI=y
CONFIG_USB_G_MULTI_RNDIS=y
CONFIG_USB_G_MULTI_CDC=y
CONFIG_USB_G_HID=y
CONFIG_USB_G_DBGP=y
# CONFIG_USB_G_DBGP_PRINTK is not set
CONFIG_USB_G_DBGP_SERIAL=y
CONFIG_USB_G_WEBCAM=y
CONFIG_USB_RAW_GADGET=y
# end of USB Gadget precomposed configurations

CONFIG_TYPEC=y
CONFIG_TYPEC_TCPM=y
CONFIG_TYPEC_TCPCI=y
CONFIG_TYPEC_RT1711H=y
CONFIG_TYPEC_MT6360=y
CONFIG_TYPEC_TCPCI_MAXIM=y
CONFIG_TYPEC_FUSB302=y
CONFIG_TYPEC_WCOVE=y
CONFIG_TYPEC_UCSI=y
CONFIG_UCSI_CCG=y
CONFIG_UCSI_ACPI=y
CONFIG_UCSI_STM32G0=y
CONFIG_TYPEC_TPS6598X=y
CONFIG_TYPEC_ANX7411=y
CONFIG_TYPEC_RT1719=y
CONFIG_TYPEC_HD3SS3220=y
CONFIG_TYPEC_STUSB160X=y
CONFIG_TYPEC_WUSB3801=y

#
# USB Type-C Multiplexer/DeMultiplexer Switch support
#
CONFIG_TYPEC_MUX_FSA4480=y
CONFIG_TYPEC_MUX_PI3USB30532=y
CONFIG_TYPEC_MUX_INTEL_PMC=y
# end of USB Type-C Multiplexer/DeMultiplexer Switch support

#
# USB Type-C Alternate Mode drivers
#
CONFIG_TYPEC_DP_ALTMODE=y
CONFIG_TYPEC_NVIDIA_ALTMODE=y
# end of USB Type-C Alternate Mode drivers

CONFIG_USB_ROLE_SWITCH=y
CONFIG_USB_ROLES_INTEL_XHCI=y
CONFIG_MMC=y
CONFIG_PWRSEQ_EMMC=y
CONFIG_PWRSEQ_SD8787=y
CONFIG_PWRSEQ_SIMPLE=y
CONFIG_MMC_BLOCK=y
CONFIG_MMC_BLOCK_MINORS=8
CONFIG_SDIO_UART=y
CONFIG_MMC_TEST=y
CONFIG_MMC_CRYPTO=y

#
# MMC/SD/SDIO Host Controller Drivers
#
CONFIG_MMC_DEBUG=y
CONFIG_MMC_SDHCI=y
CONFIG_MMC_SDHCI_IO_ACCESSORS=y
CONFIG_MMC_SDHCI_PCI=y
CONFIG_MMC_RICOH_MMC=y
CONFIG_MMC_SDHCI_ACPI=y
CONFIG_MMC_SDHCI_PLTFM=y
CONFIG_MMC_SDHCI_OF_ARASAN=y
CONFIG_MMC_SDHCI_OF_ASPEED=y
CONFIG_MMC_SDHCI_OF_ASPEED_TEST=y
CONFIG_MMC_SDHCI_OF_AT91=y
CONFIG_MMC_SDHCI_OF_DWCMSHC=y
CONFIG_MMC_SDHCI_CADENCE=y
CONFIG_MMC_SDHCI_F_SDH30=y
CONFIG_MMC_SDHCI_MILBEAUT=y
CONFIG_MMC_WBSD=y
CONFIG_MMC_ALCOR=y
CONFIG_MMC_TIFM_SD=y
CONFIG_MMC_SPI=y
CONFIG_MMC_SDRICOH_CS=y
CONFIG_MMC_CB710=y
CONFIG_MMC_VIA_SDMMC=y
CONFIG_MMC_VUB300=y
CONFIG_MMC_USHC=y
CONFIG_MMC_USDHI6ROL0=y
CONFIG_MMC_REALTEK_PCI=y
CONFIG_MMC_REALTEK_USB=y
CONFIG_MMC_CQHCI=y
CONFIG_MMC_HSQ=y
CONFIG_MMC_TOSHIBA_PCI=y
CONFIG_MMC_MTK=y
CONFIG_MMC_SDHCI_XENON=y
CONFIG_MMC_SDHCI_OMAP=y
CONFIG_MMC_SDHCI_AM654=y
CONFIG_MMC_SDHCI_EXTERNAL_DMA=y
CONFIG_MMC_LITEX=y
CONFIG_SCSI_UFSHCD=y
CONFIG_SCSI_UFS_BSG=y
CONFIG_SCSI_UFS_CRYPTO=y
CONFIG_SCSI_UFS_HPB=y
CONFIG_SCSI_UFS_FAULT_INJECTION=y
CONFIG_SCSI_UFS_HWMON=y
CONFIG_SCSI_UFSHCD_PCI=y
CONFIG_SCSI_UFS_DWC_TC_PCI=y
CONFIG_SCSI_UFSHCD_PLATFORM=y
CONFIG_SCSI_UFS_CDNS_PLATFORM=y
CONFIG_SCSI_UFS_DWC_TC_PLATFORM=y
CONFIG_MEMSTICK=y
CONFIG_MEMSTICK_DEBUG=y

#
# MemoryStick drivers
#
CONFIG_MEMSTICK_UNSAFE_RESUME=y
CONFIG_MSPRO_BLOCK=y
CONFIG_MS_BLOCK=y

#
# MemoryStick Host Controller Drivers
#
CONFIG_MEMSTICK_TIFM_MS=y
CONFIG_MEMSTICK_JMICRON_38X=y
CONFIG_MEMSTICK_R592=y
CONFIG_MEMSTICK_REALTEK_PCI=y
CONFIG_MEMSTICK_REALTEK_USB=y
CONFIG_NEW_LEDS=y
CONFIG_LEDS_CLASS=y
CONFIG_LEDS_CLASS_FLASH=y
CONFIG_LEDS_CLASS_MULTICOLOR=y
CONFIG_LEDS_BRIGHTNESS_HW_CHANGED=y

#
# LED drivers
#
CONFIG_LEDS_88PM860X=y
CONFIG_LEDS_AN30259A=y
CONFIG_LEDS_APU=y
CONFIG_LEDS_AW2013=y
CONFIG_LEDS_BCM6328=y
CONFIG_LEDS_BCM6358=y
CONFIG_LEDS_CPCAP=y
CONFIG_LEDS_CR0014114=y
CONFIG_LEDS_EL15203000=y
CONFIG_LEDS_LM3530=y
CONFIG_LEDS_LM3532=y
CONFIG_LEDS_LM3533=y
CONFIG_LEDS_LM3642=y
CONFIG_LEDS_LM3692X=y
CONFIG_LEDS_MT6323=y
CONFIG_LEDS_PCA9532=y
CONFIG_LEDS_PCA9532_GPIO=y
CONFIG_LEDS_GPIO=y
CONFIG_LEDS_LP3944=y
CONFIG_LEDS_LP3952=y
CONFIG_LEDS_LP50XX=y
CONFIG_LEDS_LP55XX_COMMON=y
CONFIG_LEDS_LP5521=y
CONFIG_LEDS_LP5523=y
CONFIG_LEDS_LP5562=y
CONFIG_LEDS_LP8501=y
CONFIG_LEDS_LP8788=y
CONFIG_LEDS_LP8860=y
CONFIG_LEDS_PCA955X=y
CONFIG_LEDS_PCA955X_GPIO=y
CONFIG_LEDS_PCA963X=y
CONFIG_LEDS_WM831X_STATUS=y
CONFIG_LEDS_WM8350=y
CONFIG_LEDS_DA903X=y
CONFIG_LEDS_DA9052=y
CONFIG_LEDS_DAC124S085=y
CONFIG_LEDS_PWM=y
CONFIG_LEDS_REGULATOR=y
CONFIG_LEDS_BD2802=y
CONFIG_LEDS_INTEL_SS4200=y
CONFIG_LEDS_LT3593=y
CONFIG_LEDS_ADP5520=y
CONFIG_LEDS_MC13783=y
CONFIG_LEDS_TCA6507=y
CONFIG_LEDS_TLC591XX=y
CONFIG_LEDS_MAX77650=y
CONFIG_LEDS_MAX8997=y
CONFIG_LEDS_LM355x=y
CONFIG_LEDS_MENF21BMC=y
CONFIG_LEDS_IS31FL319X=y
CONFIG_LEDS_IS31FL32XX=y

#
# LED driver for blink(1) USB RGB LED is under Special HID drivers (HID_THINGM)
#
CONFIG_LEDS_BLINKM=y
CONFIG_LEDS_SYSCON=y
CONFIG_LEDS_MLXCPLD=y
CONFIG_LEDS_MLXREG=y
CONFIG_LEDS_USER=y
CONFIG_LEDS_NIC78BX=y
CONFIG_LEDS_SPI_BYTE=y
CONFIG_LEDS_TI_LMU_COMMON=y
CONFIG_LEDS_LM3697=y
CONFIG_LEDS_LM36274=y
CONFIG_LEDS_TPS6105X=y
CONFIG_LEDS_LGM=y

#
# Flash and Torch LED drivers
#
CONFIG_LEDS_AAT1290=y
CONFIG_LEDS_AS3645A=y
CONFIG_LEDS_KTD2692=y
CONFIG_LEDS_LM3601X=y
CONFIG_LEDS_MAX77693=y
CONFIG_LEDS_MT6360=y
CONFIG_LEDS_RT4505=y
CONFIG_LEDS_RT8515=y
CONFIG_LEDS_SGM3140=y

#
# RGB LED drivers
#
CONFIG_LEDS_PWM_MULTICOLOR=y
CONFIG_LEDS_QCOM_LPG=y

#
# LED Triggers
#
CONFIG_LEDS_TRIGGERS=y
CONFIG_LEDS_TRIGGER_TIMER=y
CONFIG_LEDS_TRIGGER_ONESHOT=y
CONFIG_LEDS_TRIGGER_DISK=y
CONFIG_LEDS_TRIGGER_MTD=y
CONFIG_LEDS_TRIGGER_HEARTBEAT=y
CONFIG_LEDS_TRIGGER_BACKLIGHT=y
CONFIG_LEDS_TRIGGER_CPU=y
CONFIG_LEDS_TRIGGER_ACTIVITY=y
CONFIG_LEDS_TRIGGER_GPIO=y
CONFIG_LEDS_TRIGGER_DEFAULT_ON=y

#
# iptables trigger is under Netfilter config (LED target)
#
CONFIG_LEDS_TRIGGER_TRANSIENT=y
CONFIG_LEDS_TRIGGER_CAMERA=y
CONFIG_LEDS_TRIGGER_PANIC=y
CONFIG_LEDS_TRIGGER_NETDEV=y
CONFIG_LEDS_TRIGGER_PATTERN=y
CONFIG_LEDS_TRIGGER_AUDIO=y
CONFIG_LEDS_TRIGGER_TTY=y

#
# Simple LED drivers
#
CONFIG_LEDS_SIEMENS_SIMATIC_IPC=y
CONFIG_ACCESSIBILITY=y
CONFIG_A11Y_BRAILLE_CONSOLE=y

#
# Speakup console speech
#
CONFIG_SPEAKUP=y
CONFIG_SPEAKUP_SYNTH_ACNTSA=y
CONFIG_SPEAKUP_SYNTH_APOLLO=y
CONFIG_SPEAKUP_SYNTH_AUDPTR=y
CONFIG_SPEAKUP_SYNTH_BNS=y
CONFIG_SPEAKUP_SYNTH_DECTLK=y
CONFIG_SPEAKUP_SYNTH_DECEXT=y
CONFIG_SPEAKUP_SYNTH_LTLK=y
CONFIG_SPEAKUP_SYNTH_SOFT=y
CONFIG_SPEAKUP_SYNTH_SPKOUT=y
CONFIG_SPEAKUP_SYNTH_TXPRT=y
CONFIG_SPEAKUP_SYNTH_DUMMY=y
# end of Speakup console speech

CONFIG_INFINIBAND=y
CONFIG_INFINIBAND_USER_MAD=y
CONFIG_INFINIBAND_USER_ACCESS=y
CONFIG_INFINIBAND_USER_MEM=y
CONFIG_INFINIBAND_ON_DEMAND_PAGING=y
CONFIG_INFINIBAND_ADDR_TRANS=y
CONFIG_INFINIBAND_ADDR_TRANS_CONFIGFS=y
CONFIG_INFINIBAND_VIRT_DMA=y
CONFIG_INFINIBAND_BNXT_RE=y
CONFIG_INFINIBAND_CXGB4=y
CONFIG_INFINIBAND_EFA=y
CONFIG_INFINIBAND_ERDMA=y
CONFIG_INFINIBAND_HFI1=y
CONFIG_HFI1_DEBUG_SDMA_ORDER=y
CONFIG_SDMA_VERBOSITY=y
CONFIG_INFINIBAND_IRDMA=y
CONFIG_MLX4_INFINIBAND=y
CONFIG_MLX5_INFINIBAND=y
CONFIG_INFINIBAND_MTHCA=y
CONFIG_INFINIBAND_MTHCA_DEBUG=y
CONFIG_INFINIBAND_OCRDMA=y
CONFIG_INFINIBAND_QEDR=y
CONFIG_INFINIBAND_QIB=y
CONFIG_INFINIBAND_QIB_DCA=y
CONFIG_INFINIBAND_USNIC=y
CONFIG_INFINIBAND_VMWARE_PVRDMA=y
CONFIG_INFINIBAND_RDMAVT=y
CONFIG_RDMA_RXE=y
CONFIG_RDMA_SIW=y
CONFIG_INFINIBAND_IPOIB=y
CONFIG_INFINIBAND_IPOIB_CM=y
CONFIG_INFINIBAND_IPOIB_DEBUG=y
CONFIG_INFINIBAND_IPOIB_DEBUG_DATA=y
CONFIG_INFINIBAND_SRP=y
CONFIG_INFINIBAND_SRPT=y
CONFIG_INFINIBAND_ISER=y
CONFIG_INFINIBAND_ISERT=y
CONFIG_INFINIBAND_RTRS=y
CONFIG_INFINIBAND_RTRS_CLIENT=y
CONFIG_INFINIBAND_RTRS_SERVER=y
CONFIG_INFINIBAND_OPA_VNIC=y
CONFIG_EDAC_ATOMIC_SCRUB=y
CONFIG_EDAC_SUPPORT=y
CONFIG_EDAC=y
CONFIG_EDAC_LEGACY_SYSFS=y
CONFIG_EDAC_DEBUG=y
CONFIG_EDAC_DECODE_MCE=y
CONFIG_EDAC_GHES=y
CONFIG_EDAC_AMD64=y
CONFIG_EDAC_E752X=y
CONFIG_EDAC_I82975X=y
CONFIG_EDAC_I3000=y
CONFIG_EDAC_I3200=y
CONFIG_EDAC_IE31200=y
CONFIG_EDAC_X38=y
CONFIG_EDAC_I5400=y
CONFIG_EDAC_I7CORE=y
CONFIG_EDAC_I5000=y
CONFIG_EDAC_I5100=y
CONFIG_EDAC_I7300=y
CONFIG_EDAC_SBRIDGE=y
CONFIG_EDAC_SKX=y
CONFIG_EDAC_I10NM=y
CONFIG_EDAC_PND2=y
CONFIG_EDAC_IGEN6=y
CONFIG_RTC_LIB=y
CONFIG_RTC_MC146818_LIB=y
CONFIG_RTC_CLASS=y
CONFIG_RTC_HCTOSYS=y
CONFIG_RTC_HCTOSYS_DEVICE="rtc0"
CONFIG_RTC_SYSTOHC=y
CONFIG_RTC_SYSTOHC_DEVICE="rtc0"
CONFIG_RTC_DEBUG=y
CONFIG_RTC_LIB_KUNIT_TEST=y
CONFIG_RTC_NVMEM=y

#
# RTC interfaces
#
CONFIG_RTC_INTF_SYSFS=y
CONFIG_RTC_INTF_PROC=y
CONFIG_RTC_INTF_DEV=y
CONFIG_RTC_INTF_DEV_UIE_EMUL=y
CONFIG_RTC_DRV_TEST=y

#
# I2C RTC drivers
#
CONFIG_RTC_DRV_88PM860X=y
CONFIG_RTC_DRV_88PM80X=y
CONFIG_RTC_DRV_ABB5ZES3=y
CONFIG_RTC_DRV_ABEOZ9=y
CONFIG_RTC_DRV_ABX80X=y
CONFIG_RTC_DRV_AS3722=y
CONFIG_RTC_DRV_DS1307=y
CONFIG_RTC_DRV_DS1307_CENTURY=y
CONFIG_RTC_DRV_DS1374=y
CONFIG_RTC_DRV_DS1374_WDT=y
CONFIG_RTC_DRV_DS1672=y
CONFIG_RTC_DRV_HYM8563=y
CONFIG_RTC_DRV_LP8788=y
CONFIG_RTC_DRV_MAX6900=y
CONFIG_RTC_DRV_MAX8907=y
CONFIG_RTC_DRV_MAX8925=y
CONFIG_RTC_DRV_MAX8998=y
CONFIG_RTC_DRV_MAX8997=y
CONFIG_RTC_DRV_MAX77686=y
CONFIG_RTC_DRV_NCT3018Y=y
CONFIG_RTC_DRV_RK808=y
CONFIG_RTC_DRV_RS5C372=y
CONFIG_RTC_DRV_ISL1208=y
CONFIG_RTC_DRV_ISL12022=y
CONFIG_RTC_DRV_ISL12026=y
CONFIG_RTC_DRV_X1205=y
CONFIG_RTC_DRV_PCF8523=y
CONFIG_RTC_DRV_PCF85063=y
CONFIG_RTC_DRV_PCF85363=y
CONFIG_RTC_DRV_PCF8563=y
CONFIG_RTC_DRV_PCF8583=y
CONFIG_RTC_DRV_M41T80=y
CONFIG_RTC_DRV_M41T80_WDT=y
CONFIG_RTC_DRV_BD70528=y
CONFIG_RTC_DRV_BQ32K=y
CONFIG_RTC_DRV_TWL4030=y
CONFIG_RTC_DRV_PALMAS=y
CONFIG_RTC_DRV_TPS6586X=y
CONFIG_RTC_DRV_TPS65910=y
CONFIG_RTC_DRV_RC5T583=y
CONFIG_RTC_DRV_RC5T619=y
CONFIG_RTC_DRV_S35390A=y
CONFIG_RTC_DRV_FM3130=y
CONFIG_RTC_DRV_RX8010=y
CONFIG_RTC_DRV_RX8581=y
CONFIG_RTC_DRV_RX8025=y
CONFIG_RTC_DRV_EM3027=y
CONFIG_RTC_DRV_RV3028=y
CONFIG_RTC_DRV_RV3032=y
CONFIG_RTC_DRV_RV8803=y
CONFIG_RTC_DRV_S5M=y
CONFIG_RTC_DRV_SD3078=y

#
# SPI RTC drivers
#
CONFIG_RTC_DRV_M41T93=y
CONFIG_RTC_DRV_M41T94=y
CONFIG_RTC_DRV_DS1302=y
CONFIG_RTC_DRV_DS1305=y
CONFIG_RTC_DRV_DS1343=y
CONFIG_RTC_DRV_DS1347=y
CONFIG_RTC_DRV_DS1390=y
CONFIG_RTC_DRV_MAX6916=y
CONFIG_RTC_DRV_R9701=y
CONFIG_RTC_DRV_RX4581=y
CONFIG_RTC_DRV_RS5C348=y
CONFIG_RTC_DRV_MAX6902=y
CONFIG_RTC_DRV_PCF2123=y
CONFIG_RTC_DRV_MCP795=y
CONFIG_RTC_I2C_AND_SPI=y

#
# SPI and I2C RTC drivers
#
CONFIG_RTC_DRV_DS3232=y
CONFIG_RTC_DRV_DS3232_HWMON=y
CONFIG_RTC_DRV_PCF2127=y
CONFIG_RTC_DRV_RV3029C2=y
CONFIG_RTC_DRV_RV3029_HWMON=y
CONFIG_RTC_DRV_RX6110=y

#
# Platform RTC drivers
#
CONFIG_RTC_DRV_CMOS=y
CONFIG_RTC_DRV_DS1286=y
CONFIG_RTC_DRV_DS1511=y
CONFIG_RTC_DRV_DS1553=y
CONFIG_RTC_DRV_DS1685_FAMILY=y
CONFIG_RTC_DRV_DS1685=y
# CONFIG_RTC_DRV_DS1689 is not set
# CONFIG_RTC_DRV_DS17285 is not set
# CONFIG_RTC_DRV_DS17485 is not set
# CONFIG_RTC_DRV_DS17885 is not set
CONFIG_RTC_DRV_DS1742=y
CONFIG_RTC_DRV_DS2404=y
CONFIG_RTC_DRV_DA9052=y
CONFIG_RTC_DRV_DA9055=y
CONFIG_RTC_DRV_DA9063=y
CONFIG_RTC_DRV_STK17TA8=y
CONFIG_RTC_DRV_M48T86=y
CONFIG_RTC_DRV_M48T35=y
CONFIG_RTC_DRV_M48T59=y
CONFIG_RTC_DRV_MSM6242=y
CONFIG_RTC_DRV_BQ4802=y
CONFIG_RTC_DRV_RP5C01=y
CONFIG_RTC_DRV_V3020=y
CONFIG_RTC_DRV_WM831X=y
CONFIG_RTC_DRV_WM8350=y
CONFIG_RTC_DRV_PCF50633=y
CONFIG_RTC_DRV_ZYNQMP=y
CONFIG_RTC_DRV_CROS_EC=y
CONFIG_RTC_DRV_NTXEC=y

#
# on-CPU RTC drivers
#
CONFIG_RTC_DRV_CADENCE=y
CONFIG_RTC_DRV_FTRTC010=y
CONFIG_RTC_DRV_PCAP=y
CONFIG_RTC_DRV_MC13XXX=y
CONFIG_RTC_DRV_MT6397=y
CONFIG_RTC_DRV_R7301=y
CONFIG_RTC_DRV_CPCAP=y

#
# HID Sensor RTC drivers
#
CONFIG_RTC_DRV_HID_SENSOR_TIME=y
CONFIG_RTC_DRV_GOLDFISH=y
CONFIG_RTC_DRV_WILCO_EC=y
CONFIG_DMADEVICES=y
CONFIG_DMADEVICES_DEBUG=y
CONFIG_DMADEVICES_VDEBUG=y

#
# DMA Devices
#
CONFIG_DMA_ENGINE=y
CONFIG_DMA_VIRTUAL_CHANNELS=y
CONFIG_DMA_ACPI=y
CONFIG_DMA_OF=y
CONFIG_ALTERA_MSGDMA=y
CONFIG_DW_AXI_DMAC=y
CONFIG_FSL_EDMA=y
CONFIG_INTEL_IDMA64=y
CONFIG_INTEL_IDXD_BUS=y
CONFIG_INTEL_IDXD=y
CONFIG_INTEL_IDXD_COMPAT=y
CONFIG_INTEL_IDXD_SVM=y
CONFIG_INTEL_IDXD_PERFMON=y
CONFIG_INTEL_IOATDMA=y
CONFIG_PLX_DMA=y
CONFIG_XILINX_ZYNQMP_DPDMA=y
CONFIG_AMD_PTDMA=y
CONFIG_QCOM_HIDMA_MGMT=y
CONFIG_QCOM_HIDMA=y
CONFIG_DW_DMAC_CORE=y
CONFIG_DW_DMAC=y
CONFIG_DW_DMAC_PCI=y
CONFIG_DW_EDMA=y
CONFIG_DW_EDMA_PCIE=y
CONFIG_HSU_DMA=y
CONFIG_HSU_DMA_PCI=y
CONFIG_SF_PDMA=y
CONFIG_INTEL_LDMA=y

#
# DMA Clients
#
CONFIG_ASYNC_TX_DMA=y
CONFIG_DMATEST=y
CONFIG_DMA_ENGINE_RAID=y

#
# DMABUF options
#
CONFIG_SYNC_FILE=y
CONFIG_SW_SYNC=y
CONFIG_UDMABUF=y
CONFIG_DMABUF_MOVE_NOTIFY=y
CONFIG_DMABUF_DEBUG=y
CONFIG_DMABUF_SELFTESTS=y
CONFIG_DMABUF_HEAPS=y
CONFIG_DMABUF_SYSFS_STATS=y
CONFIG_DMABUF_HEAPS_SYSTEM=y
CONFIG_DMABUF_HEAPS_CMA=y
# end of DMABUF options

CONFIG_DCA=y
CONFIG_AUXDISPLAY=y
CONFIG_CHARLCD=y
CONFIG_LINEDISP=y
CONFIG_HD44780_COMMON=y
CONFIG_HD44780=y
CONFIG_KS0108=y
CONFIG_KS0108_PORT=0x378
CONFIG_KS0108_DELAY=2
CONFIG_CFAG12864B=y
CONFIG_CFAG12864B_RATE=20
CONFIG_IMG_ASCII_LCD=y
CONFIG_HT16K33=y
CONFIG_LCD2S=y
CONFIG_PARPORT_PANEL=y
CONFIG_PANEL_PARPORT=0
CONFIG_PANEL_PROFILE=5
CONFIG_PANEL_CHANGE_MESSAGE=y
CONFIG_PANEL_BOOT_MESSAGE=""
# CONFIG_CHARLCD_BL_OFF is not set
# CONFIG_CHARLCD_BL_ON is not set
CONFIG_CHARLCD_BL_FLASH=y
CONFIG_PANEL=y
CONFIG_UIO=y
CONFIG_UIO_CIF=y
CONFIG_UIO_PDRV_GENIRQ=y
CONFIG_UIO_DMEM_GENIRQ=y
CONFIG_UIO_AEC=y
CONFIG_UIO_SERCOS3=y
CONFIG_UIO_PCI_GENERIC=y
CONFIG_UIO_NETX=y
CONFIG_UIO_PRUSS=y
CONFIG_UIO_MF624=y
CONFIG_UIO_HV_GENERIC=y
CONFIG_UIO_DFL=y
CONFIG_VFIO=y
CONFIG_VFIO_IOMMU_TYPE1=y
CONFIG_VFIO_VIRQFD=y
CONFIG_VFIO_NOIOMMU=y
CONFIG_VFIO_PCI_CORE=y
CONFIG_VFIO_PCI_MMAP=y
CONFIG_VFIO_PCI_INTX=y
CONFIG_VFIO_PCI=y
CONFIG_VFIO_PCI_VGA=y
CONFIG_VFIO_PCI_IGD=y
CONFIG_MLX5_VFIO_PCI=y
CONFIG_VFIO_MDEV=y
CONFIG_IRQ_BYPASS_MANAGER=y
CONFIG_VIRT_DRIVERS=y
CONFIG_VMGENID=y
CONFIG_VBOXGUEST=y
CONFIG_NITRO_ENCLAVES=y
CONFIG_NITRO_ENCLAVES_MISC_DEV_TEST=y
CONFIG_ACRN_HSM=y
CONFIG_EFI_SECRET=y
CONFIG_SEV_GUEST=y
CONFIG_VIRTIO_ANCHOR=y
CONFIG_VIRTIO=y
CONFIG_VIRTIO_PCI_LIB=y
CONFIG_VIRTIO_PCI_LIB_LEGACY=y
CONFIG_VIRTIO_MENU=y
CONFIG_VIRTIO_PCI=y
CONFIG_VIRTIO_PCI_LEGACY=y
CONFIG_VIRTIO_VDPA=y
CONFIG_VIRTIO_PMEM=y
CONFIG_VIRTIO_BALLOON=y
CONFIG_VIRTIO_MEM=y
CONFIG_VIRTIO_INPUT=y
CONFIG_VIRTIO_MMIO=y
CONFIG_VIRTIO_MMIO_CMDLINE_DEVICES=y
CONFIG_VIRTIO_DMA_SHARED_BUFFER=y
CONFIG_VDPA=y
CONFIG_VDPA_SIM=y
CONFIG_VDPA_SIM_NET=y
CONFIG_VDPA_SIM_BLOCK=y
CONFIG_VDPA_USER=y
CONFIG_IFCVF=y
CONFIG_MLX5_VDPA=y
CONFIG_MLX5_VDPA_NET=y
CONFIG_VP_VDPA=y
CONFIG_ALIBABA_ENI_VDPA=y
CONFIG_VHOST_IOTLB=y
CONFIG_VHOST_RING=y
CONFIG_VHOST=y
CONFIG_VHOST_MENU=y
CONFIG_VHOST_NET=y
CONFIG_VHOST_SCSI=y
CONFIG_VHOST_VSOCK=y
CONFIG_VHOST_VDPA=y
CONFIG_VHOST_CROSS_ENDIAN_LEGACY=y

#
# Microsoft Hyper-V guest support
#
CONFIG_HYPERV=y
CONFIG_HYPERV_TIMER=y
CONFIG_HYPERV_UTILS=y
CONFIG_HYPERV_BALLOON=y
# end of Microsoft Hyper-V guest support

#
# Xen driver support
#
CONFIG_XEN_BALLOON=y
CONFIG_XEN_BALLOON_MEMORY_HOTPLUG=y
CONFIG_XEN_MEMORY_HOTPLUG_LIMIT=512
CONFIG_XEN_SCRUB_PAGES_DEFAULT=y
CONFIG_XEN_DEV_EVTCHN=y
CONFIG_XEN_BACKEND=y
CONFIG_XENFS=y
CONFIG_XEN_COMPAT_XENFS=y
CONFIG_XEN_SYS_HYPERVISOR=y
CONFIG_XEN_XENBUS_FRONTEND=y
CONFIG_XEN_GNTDEV=y
CONFIG_XEN_GNTDEV_DMABUF=y
CONFIG_XEN_GRANT_DEV_ALLOC=y
CONFIG_XEN_GRANT_DMA_ALLOC=y
CONFIG_SWIOTLB_XEN=y
CONFIG_XEN_PCI_STUB=y
CONFIG_XEN_PCIDEV_BACKEND=y
CONFIG_XEN_PVCALLS_FRONTEND=y
CONFIG_XEN_PVCALLS_BACKEND=y
CONFIG_XEN_SCSI_BACKEND=y
CONFIG_XEN_PRIVCMD=y
CONFIG_XEN_ACPI_PROCESSOR=y
CONFIG_XEN_MCE_LOG=y
CONFIG_XEN_HAVE_PVMMU=y
CONFIG_XEN_EFI=y
CONFIG_XEN_AUTO_XLATE=y
CONFIG_XEN_ACPI=y
CONFIG_XEN_SYMS=y
CONFIG_XEN_HAVE_VPMU=y
CONFIG_XEN_FRONT_PGDIR_SHBUF=y
CONFIG_XEN_UNPOPULATED_ALLOC=y
CONFIG_XEN_GRANT_DMA_IOMMU=y
CONFIG_XEN_GRANT_DMA_OPS=y
CONFIG_XEN_VIRTIO=y
CONFIG_XEN_VIRTIO_FORCE_GRANT=y
# end of Xen driver support

CONFIG_GREYBUS=y
CONFIG_GREYBUS_ES2=y
CONFIG_COMEDI=y
CONFIG_COMEDI_DEBUG=y
CONFIG_COMEDI_DEFAULT_BUF_SIZE_KB=2048
CONFIG_COMEDI_DEFAULT_BUF_MAXSIZE_KB=20480
CONFIG_COMEDI_MISC_DRIVERS=y
CONFIG_COMEDI_BOND=y
CONFIG_COMEDI_TEST=y
CONFIG_COMEDI_PARPORT=y
CONFIG_COMEDI_ISA_DRIVERS=y
CONFIG_COMEDI_PCL711=y
CONFIG_COMEDI_PCL724=y
CONFIG_COMEDI_PCL726=y
CONFIG_COMEDI_PCL730=y
CONFIG_COMEDI_PCL812=y
CONFIG_COMEDI_PCL816=y
CONFIG_COMEDI_PCL818=y
CONFIG_COMEDI_PCM3724=y
CONFIG_COMEDI_AMPLC_DIO200_ISA=y
CONFIG_COMEDI_AMPLC_PC236_ISA=y
CONFIG_COMEDI_AMPLC_PC263_ISA=y
CONFIG_COMEDI_RTI800=y
CONFIG_COMEDI_RTI802=y
CONFIG_COMEDI_DAC02=y
CONFIG_COMEDI_DAS16M1=y
CONFIG_COMEDI_DAS08_ISA=y
CONFIG_COMEDI_DAS16=y
CONFIG_COMEDI_DAS800=y
CONFIG_COMEDI_DAS1800=y
CONFIG_COMEDI_DAS6402=y
CONFIG_COMEDI_DT2801=y
CONFIG_COMEDI_DT2811=y
CONFIG_COMEDI_DT2814=y
CONFIG_COMEDI_DT2815=y
CONFIG_COMEDI_DT2817=y
CONFIG_COMEDI_DT282X=y
CONFIG_COMEDI_DMM32AT=y
CONFIG_COMEDI_FL512=y
CONFIG_COMEDI_AIO_AIO12_8=y
CONFIG_COMEDI_AIO_IIRO_16=y
CONFIG_COMEDI_II_PCI20KC=y
CONFIG_COMEDI_C6XDIGIO=y
CONFIG_COMEDI_MPC624=y
CONFIG_COMEDI_ADQ12B=y
CONFIG_COMEDI_NI_AT_A2150=y
CONFIG_COMEDI_NI_AT_AO=y
CONFIG_COMEDI_NI_ATMIO=y
CONFIG_COMEDI_NI_ATMIO16D=y
CONFIG_COMEDI_NI_LABPC_ISA=y
CONFIG_COMEDI_PCMAD=y
CONFIG_COMEDI_PCMDA12=y
CONFIG_COMEDI_PCMMIO=y
CONFIG_COMEDI_PCMUIO=y
CONFIG_COMEDI_MULTIQ3=y
CONFIG_COMEDI_S526=y
CONFIG_COMEDI_PCI_DRIVERS=y
CONFIG_COMEDI_8255_PCI=y
CONFIG_COMEDI_ADDI_WATCHDOG=y
CONFIG_COMEDI_ADDI_APCI_1032=y
CONFIG_COMEDI_ADDI_APCI_1500=y
CONFIG_COMEDI_ADDI_APCI_1516=y
CONFIG_COMEDI_ADDI_APCI_1564=y
CONFIG_COMEDI_ADDI_APCI_16XX=y
CONFIG_COMEDI_ADDI_APCI_2032=y
CONFIG_COMEDI_ADDI_APCI_2200=y
CONFIG_COMEDI_ADDI_APCI_3120=y
CONFIG_COMEDI_ADDI_APCI_3501=y
CONFIG_COMEDI_ADDI_APCI_3XXX=y
CONFIG_COMEDI_ADL_PCI6208=y
CONFIG_COMEDI_ADL_PCI7X3X=y
CONFIG_COMEDI_ADL_PCI8164=y
CONFIG_COMEDI_ADL_PCI9111=y
CONFIG_COMEDI_ADL_PCI9118=y
CONFIG_COMEDI_ADV_PCI1710=y
CONFIG_COMEDI_ADV_PCI1720=y
CONFIG_COMEDI_ADV_PCI1723=y
CONFIG_COMEDI_ADV_PCI1724=y
CONFIG_COMEDI_ADV_PCI1760=y
CONFIG_COMEDI_ADV_PCI_DIO=y
CONFIG_COMEDI_AMPLC_DIO200_PCI=y
CONFIG_COMEDI_AMPLC_PC236_PCI=y
CONFIG_COMEDI_AMPLC_PC263_PCI=y
CONFIG_COMEDI_AMPLC_PCI224=y
CONFIG_COMEDI_AMPLC_PCI230=y
CONFIG_COMEDI_CONTEC_PCI_DIO=y
CONFIG_COMEDI_DAS08_PCI=y
CONFIG_COMEDI_DT3000=y
CONFIG_COMEDI_DYNA_PCI10XX=y
CONFIG_COMEDI_GSC_HPDI=y
CONFIG_COMEDI_MF6X4=y
CONFIG_COMEDI_ICP_MULTI=y
CONFIG_COMEDI_DAQBOARD2000=y
CONFIG_COMEDI_JR3_PCI=y
CONFIG_COMEDI_KE_COUNTER=y
CONFIG_COMEDI_CB_PCIDAS64=y
CONFIG_COMEDI_CB_PCIDAS=y
CONFIG_COMEDI_CB_PCIDDA=y
CONFIG_COMEDI_CB_PCIMDAS=y
CONFIG_COMEDI_CB_PCIMDDA=y
CONFIG_COMEDI_ME4000=y
CONFIG_COMEDI_ME_DAQ=y
CONFIG_COMEDI_NI_6527=y
CONFIG_COMEDI_NI_65XX=y
CONFIG_COMEDI_NI_660X=y
CONFIG_COMEDI_NI_670X=y
CONFIG_COMEDI_NI_LABPC_PCI=y
CONFIG_COMEDI_NI_PCIDIO=y
CONFIG_COMEDI_NI_PCIMIO=y
CONFIG_COMEDI_RTD520=y
CONFIG_COMEDI_S626=y
CONFIG_COMEDI_MITE=y
CONFIG_COMEDI_NI_TIOCMD=y
CONFIG_COMEDI_PCMCIA_DRIVERS=y
CONFIG_COMEDI_CB_DAS16_CS=y
CONFIG_COMEDI_DAS08_CS=y
CONFIG_COMEDI_NI_DAQ_700_CS=y
CONFIG_COMEDI_NI_DAQ_DIO24_CS=y
CONFIG_COMEDI_NI_LABPC_CS=y
CONFIG_COMEDI_NI_MIO_CS=y
CONFIG_COMEDI_QUATECH_DAQP_CS=y
CONFIG_COMEDI_USB_DRIVERS=y
CONFIG_COMEDI_DT9812=y
CONFIG_COMEDI_NI_USB6501=y
CONFIG_COMEDI_USBDUX=y
CONFIG_COMEDI_USBDUXFAST=y
CONFIG_COMEDI_USBDUXSIGMA=y
CONFIG_COMEDI_VMK80XX=y
CONFIG_COMEDI_8254=y
CONFIG_COMEDI_8255=y
CONFIG_COMEDI_8255_SA=y
CONFIG_COMEDI_KCOMEDILIB=y
CONFIG_COMEDI_AMPLC_DIO200=y
CONFIG_COMEDI_AMPLC_PC236=y
CONFIG_COMEDI_DAS08=y
CONFIG_COMEDI_ISADMA=y
CONFIG_COMEDI_NI_LABPC=y
CONFIG_COMEDI_NI_LABPC_ISADMA=y
CONFIG_COMEDI_NI_TIO=y
CONFIG_COMEDI_NI_ROUTING=y
CONFIG_COMEDI_TESTS=y
CONFIG_COMEDI_TESTS_EXAMPLE=y
CONFIG_COMEDI_TESTS_NI_ROUTES=y
CONFIG_STAGING=y
CONFIG_PRISM2_USB=y
CONFIG_RTL8192U=m
CONFIG_RTLLIB=m
CONFIG_RTLLIB_CRYPTO_CCMP=m
CONFIG_RTLLIB_CRYPTO_TKIP=m
CONFIG_RTLLIB_CRYPTO_WEP=m
CONFIG_RTL8192E=m
CONFIG_RTL8723BS=m
CONFIG_R8712U=y
CONFIG_R8188EU=m
CONFIG_RTS5208=y
CONFIG_VT6655=m
CONFIG_VT6656=m

#
# IIO staging drivers
#

#
# Accelerometers
#
CONFIG_ADIS16203=y
CONFIG_ADIS16240=y
# end of Accelerometers

#
# Analog to digital converters
#
CONFIG_AD7816=y
# end of Analog to digital converters

#
# Analog digital bi-direction converters
#
CONFIG_ADT7316=y
CONFIG_ADT7316_SPI=y
CONFIG_ADT7316_I2C=y
# end of Analog digital bi-direction converters

#
# Capacitance to digital converters
#
CONFIG_AD7746=y
# end of Capacitance to digital converters

#
# Direct Digital Synthesis
#
CONFIG_AD9832=y
CONFIG_AD9834=y
# end of Direct Digital Synthesis

#
# Network Analyzer, Impedance Converters
#
CONFIG_AD5933=y
# end of Network Analyzer, Impedance Converters

#
# Active energy metering IC
#
CONFIG_ADE7854=y
CONFIG_ADE7854_I2C=y
CONFIG_ADE7854_SPI=y
# end of Active energy metering IC

#
# Resolver to digital converters
#
CONFIG_AD2S1210=y
# end of Resolver to digital converters
# end of IIO staging drivers

CONFIG_FB_SM750=y
CONFIG_STAGING_MEDIA=y
CONFIG_INTEL_ATOMISP=y
CONFIG_VIDEO_ATOMISP=y
CONFIG_VIDEO_ATOMISP_ISP2401=y
CONFIG_VIDEO_ATOMISP_OV2722=y
CONFIG_VIDEO_ATOMISP_GC2235=y
CONFIG_VIDEO_ATOMISP_MSRLIST_HELPER=y
CONFIG_VIDEO_ATOMISP_MT9M114=y
CONFIG_VIDEO_ATOMISP_GC0310=y
CONFIG_VIDEO_ATOMISP_OV2680=y
CONFIG_VIDEO_ATOMISP_OV5693=y
CONFIG_VIDEO_ATOMISP_LM3554=y
CONFIG_DVB_AV7110_IR=y
CONFIG_DVB_AV7110=y
CONFIG_DVB_AV7110_OSD=y
CONFIG_DVB_BUDGET_PATCH=y
CONFIG_DVB_SP8870=y
CONFIG_VIDEO_IPU3_IMGU=y
CONFIG_VIDEO_MAX96712=y
CONFIG_VIDEO_STKWEBCAM=y
CONFIG_VIDEO_ZORAN=y
CONFIG_VIDEO_ZORAN_DC30=y
CONFIG_VIDEO_ZORAN_ZR36060=y
CONFIG_VIDEO_ZORAN_BUZ=y
CONFIG_VIDEO_ZORAN_DC10=y
CONFIG_VIDEO_ZORAN_LML33=y
CONFIG_VIDEO_ZORAN_LML33R10=y
CONFIG_VIDEO_ZORAN_AVS6EYES=y
CONFIG_STAGING_BOARD=y
CONFIG_LTE_GDM724X=m
CONFIG_FIREWIRE_SERIAL=y
CONFIG_FWTTY_MAX_TOTAL_PORTS=64
CONFIG_FWTTY_MAX_CARD_PORTS=32
CONFIG_COMMON_CLK_XLNX_CLKWZRD=y
CONFIG_FB_TFT=y
CONFIG_FB_TFT_AGM1264K_FL=y
CONFIG_FB_TFT_BD663474=y
CONFIG_FB_TFT_HX8340BN=y
CONFIG_FB_TFT_HX8347D=y
CONFIG_FB_TFT_HX8353D=y
CONFIG_FB_TFT_HX8357D=y
CONFIG_FB_TFT_ILI9163=y
CONFIG_FB_TFT_ILI9320=y
CONFIG_FB_TFT_ILI9325=y
CONFIG_FB_TFT_ILI9340=y
CONFIG_FB_TFT_ILI9341=y
CONFIG_FB_TFT_ILI9481=y
CONFIG_FB_TFT_ILI9486=y
CONFIG_FB_TFT_PCD8544=y
CONFIG_FB_TFT_RA8875=y
CONFIG_FB_TFT_S6D02A1=y
CONFIG_FB_TFT_S6D1121=y
CONFIG_FB_TFT_SEPS525=y
CONFIG_FB_TFT_SH1106=y
CONFIG_FB_TFT_SSD1289=y
CONFIG_FB_TFT_SSD1305=y
CONFIG_FB_TFT_SSD1306=y
CONFIG_FB_TFT_SSD1331=y
CONFIG_FB_TFT_SSD1351=y
CONFIG_FB_TFT_ST7735R=y
CONFIG_FB_TFT_ST7789V=y
CONFIG_FB_TFT_TINYLCD=y
CONFIG_FB_TFT_TLS8204=y
CONFIG_FB_TFT_UC1611=y
CONFIG_FB_TFT_UC1701=y
CONFIG_FB_TFT_UPD161704=y
CONFIG_MOST_COMPONENTS=y
CONFIG_MOST_NET=y
CONFIG_MOST_VIDEO=y
CONFIG_MOST_DIM2=y
CONFIG_MOST_I2C=y
CONFIG_KS7010=y
CONFIG_GREYBUS_AUDIO=y
CONFIG_GREYBUS_AUDIO_APB_CODEC=y
CONFIG_GREYBUS_BOOTROM=y
CONFIG_GREYBUS_FIRMWARE=y
CONFIG_GREYBUS_HID=y
CONFIG_GREYBUS_LIGHT=y
CONFIG_GREYBUS_LOG=y
CONFIG_GREYBUS_LOOPBACK=y
CONFIG_GREYBUS_POWER=y
CONFIG_GREYBUS_RAW=y
CONFIG_GREYBUS_VIBRATOR=y
CONFIG_GREYBUS_BRIDGED_PHY=y
CONFIG_GREYBUS_GPIO=y
CONFIG_GREYBUS_I2C=y
CONFIG_GREYBUS_PWM=y
CONFIG_GREYBUS_SDIO=y
CONFIG_GREYBUS_SPI=y
CONFIG_GREYBUS_UART=y
CONFIG_GREYBUS_USB=y
CONFIG_PI433=y
CONFIG_XIL_AXIS_FIFO=y
CONFIG_FIELDBUS_DEV=y
CONFIG_HMS_ANYBUSS_BUS=y
CONFIG_ARCX_ANYBUS_CONTROLLER=y
CONFIG_HMS_PROFINET=y
CONFIG_QLGE=y
CONFIG_VME_BUS=y

#
# VME Bridge Drivers
#
CONFIG_VME_TSI148=y
CONFIG_VME_FAKE=y

#
# VME Device Drivers
#
CONFIG_VME_USER=y
CONFIG_GOLDFISH_PIPE=y
CONFIG_CHROME_PLATFORMS=y
CONFIG_CHROMEOS_ACPI=y
CONFIG_CHROMEOS_LAPTOP=y
CONFIG_CHROMEOS_PSTORE=y
CONFIG_CHROMEOS_TBMC=y
CONFIG_CROS_EC=y
CONFIG_CROS_EC_I2C=y
CONFIG_CROS_EC_RPMSG=y
CONFIG_CROS_EC_ISHTP=y
CONFIG_CROS_EC_SPI=y
CONFIG_CROS_EC_LPC=y
CONFIG_CROS_EC_PROTO=y
CONFIG_CROS_KBD_LED_BACKLIGHT=y
CONFIG_CROS_EC_CHARDEV=y
CONFIG_CROS_EC_LIGHTBAR=y
CONFIG_CROS_EC_VBC=y
CONFIG_CROS_EC_DEBUGFS=y
CONFIG_CROS_EC_SENSORHUB=y
CONFIG_CROS_EC_SYSFS=y
CONFIG_CROS_EC_TYPEC=y
CONFIG_CROS_USBPD_LOGGER=y
CONFIG_CROS_USBPD_NOTIFY=y
CONFIG_CHROMEOS_PRIVACY_SCREEN=y
CONFIG_WILCO_EC=y
CONFIG_WILCO_EC_DEBUGFS=y
CONFIG_WILCO_EC_EVENTS=y
CONFIG_WILCO_EC_TELEMETRY=y
CONFIG_CROS_KUNIT=y
CONFIG_MELLANOX_PLATFORM=y
CONFIG_MLXREG_HOTPLUG=y
CONFIG_MLXREG_IO=y
CONFIG_MLXREG_LC=y
CONFIG_NVSW_SN2201=y
CONFIG_SURFACE_PLATFORMS=y
CONFIG_SURFACE3_WMI=y
CONFIG_SURFACE_3_POWER_OPREGION=y
CONFIG_SURFACE_ACPI_NOTIFY=y
CONFIG_SURFACE_AGGREGATOR_CDEV=y
CONFIG_SURFACE_AGGREGATOR_HUB=y
CONFIG_SURFACE_AGGREGATOR_REGISTRY=y
CONFIG_SURFACE_AGGREGATOR_TABLET_SWITCH=y
CONFIG_SURFACE_DTX=y
CONFIG_SURFACE_GPE=y
CONFIG_SURFACE_HOTPLUG=y
CONFIG_SURFACE_PLATFORM_PROFILE=y
CONFIG_SURFACE_PRO3_BUTTON=y
CONFIG_SURFACE_AGGREGATOR=y
CONFIG_SURFACE_AGGREGATOR_BUS=y
CONFIG_SURFACE_AGGREGATOR_ERROR_INJECTION=y
CONFIG_X86_PLATFORM_DEVICES=y
CONFIG_ACPI_WMI=y
CONFIG_WMI_BMOF=y
CONFIG_HUAWEI_WMI=y
CONFIG_UV_SYSFS=y
CONFIG_MXM_WMI=y
CONFIG_PEAQ_WMI=y
CONFIG_NVIDIA_WMI_EC_BACKLIGHT=y
CONFIG_XIAOMI_WMI=y
CONFIG_GIGABYTE_WMI=y
CONFIG_YOGABOOK_WMI=y
CONFIG_ACERHDF=y
CONFIG_ACER_WIRELESS=y
CONFIG_ACER_WMI=y
CONFIG_AMD_PMC=y
CONFIG_AMD_HSMP=y
CONFIG_ADV_SWBUTTON=y
CONFIG_APPLE_GMUX=y
CONFIG_ASUS_LAPTOP=y
CONFIG_ASUS_WIRELESS=y
CONFIG_ASUS_WMI=y
CONFIG_ASUS_NB_WMI=y
CONFIG_ASUS_TF103C_DOCK=y
CONFIG_MERAKI_MX100=y
CONFIG_EEEPC_LAPTOP=y
CONFIG_EEEPC_WMI=y
CONFIG_X86_PLATFORM_DRIVERS_DELL=y
CONFIG_ALIENWARE_WMI=y
CONFIG_DCDBAS=y
CONFIG_DELL_LAPTOP=y
CONFIG_DELL_RBU=y
CONFIG_DELL_RBTN=y
CONFIG_DELL_SMBIOS=y
CONFIG_DELL_SMBIOS_WMI=y
CONFIG_DELL_SMBIOS_SMM=y
CONFIG_DELL_SMO8800=y
CONFIG_DELL_WMI=y
CONFIG_DELL_WMI_PRIVACY=y
CONFIG_DELL_WMI_AIO=y
CONFIG_DELL_WMI_DESCRIPTOR=y
CONFIG_DELL_WMI_LED=y
CONFIG_DELL_WMI_SYSMAN=y
CONFIG_AMILO_RFKILL=y
CONFIG_FUJITSU_LAPTOP=y
CONFIG_FUJITSU_TABLET=y
CONFIG_GPD_POCKET_FAN=y
CONFIG_HP_ACCEL=y
CONFIG_WIRELESS_HOTKEY=y
CONFIG_HP_WMI=y
CONFIG_IBM_RTL=y
CONFIG_IDEAPAD_LAPTOP=y
CONFIG_SENSORS_HDAPS=y
CONFIG_THINKPAD_ACPI=y
CONFIG_THINKPAD_ACPI_ALSA_SUPPORT=y
CONFIG_THINKPAD_ACPI_DEBUGFACILITIES=y
CONFIG_THINKPAD_ACPI_DEBUG=y
CONFIG_THINKPAD_ACPI_UNSAFE_LEDS=y
CONFIG_THINKPAD_ACPI_VIDEO=y
CONFIG_THINKPAD_ACPI_HOTKEY_POLL=y
CONFIG_THINKPAD_LMI=y
CONFIG_INTEL_ATOMISP2_PDX86=y
CONFIG_INTEL_ATOMISP2_LED=y
CONFIG_INTEL_SAR_INT1092=y
CONFIG_INTEL_SKL_INT3472=y
CONFIG_INTEL_PMC_CORE=y
CONFIG_INTEL_PMT_CLASS=y
CONFIG_INTEL_PMT_TELEMETRY=y
CONFIG_INTEL_PMT_CRASHLOG=y

#
# Intel Speed Select Technology interface support
#
CONFIG_INTEL_SPEED_SELECT_INTERFACE=y
# end of Intel Speed Select Technology interface support

CONFIG_INTEL_TELEMETRY=y
CONFIG_INTEL_WMI=y
CONFIG_INTEL_WMI_SBL_FW_UPDATE=y
CONFIG_INTEL_WMI_THUNDERBOLT=y

#
# Intel Uncore Frequency Control
#
CONFIG_INTEL_UNCORE_FREQ_CONTROL=y
# end of Intel Uncore Frequency Control

CONFIG_INTEL_HID_EVENT=y
CONFIG_INTEL_VBTN=y
CONFIG_INTEL_INT0002_VGPIO=y
CONFIG_INTEL_OAKTRAIL=y
CONFIG_INTEL_BXTWC_PMIC_TMU=y
CONFIG_INTEL_CHTDC_TI_PWRBTN=y
CONFIG_INTEL_CHTWC_INT33FE=y
CONFIG_INTEL_ISHTP_ECLITE=y
CONFIG_INTEL_MRFLD_PWRBTN=y
CONFIG_INTEL_PUNIT_IPC=y
CONFIG_INTEL_RST=y
CONFIG_INTEL_SDSI=y
CONFIG_INTEL_SMARTCONNECT=y
CONFIG_INTEL_TURBO_MAX_3=y
CONFIG_INTEL_VSEC=y
CONFIG_MSI_LAPTOP=y
CONFIG_MSI_WMI=y
CONFIG_PCENGINES_APU2=y
CONFIG_BARCO_P50_GPIO=y
CONFIG_SAMSUNG_LAPTOP=y
CONFIG_SAMSUNG_Q10=y
CONFIG_ACPI_TOSHIBA=y
CONFIG_TOSHIBA_BT_RFKILL=y
CONFIG_TOSHIBA_HAPS=y
CONFIG_TOSHIBA_WMI=y
CONFIG_ACPI_CMPC=y
CONFIG_COMPAL_LAPTOP=y
CONFIG_LG_LAPTOP=y
CONFIG_PANASONIC_LAPTOP=y
CONFIG_SONY_LAPTOP=y
CONFIG_SONYPI_COMPAT=y
CONFIG_SYSTEM76_ACPI=y
CONFIG_TOPSTAR_LAPTOP=y
CONFIG_SERIAL_MULTI_INSTANTIATE=y
CONFIG_MLX_PLATFORM=y
CONFIG_TOUCHSCREEN_DMI=y
CONFIG_X86_ANDROID_TABLETS=y
CONFIG_FW_ATTR_CLASS=y
CONFIG_INTEL_IPS=y
CONFIG_INTEL_SCU_IPC=y
CONFIG_INTEL_SCU=y
CONFIG_INTEL_SCU_PCI=y
CONFIG_INTEL_SCU_PLATFORM=y
CONFIG_INTEL_SCU_WDT=y
CONFIG_INTEL_SCU_IPC_UTIL=y
CONFIG_SIEMENS_SIMATIC_IPC=y
CONFIG_WINMATE_FM07_KEYS=y
CONFIG_P2SB=y
CONFIG_HAVE_CLK=y
CONFIG_HAVE_CLK_PREPARE=y
CONFIG_COMMON_CLK=y
CONFIG_COMMON_CLK_WM831X=y
CONFIG_LMK04832=y
CONFIG_COMMON_CLK_MAX77686=y
CONFIG_COMMON_CLK_MAX9485=y
CONFIG_COMMON_CLK_RK808=y
CONFIG_COMMON_CLK_SI5341=y
CONFIG_COMMON_CLK_SI5351=y
CONFIG_COMMON_CLK_SI514=y
CONFIG_COMMON_CLK_SI544=y
CONFIG_COMMON_CLK_SI570=y
CONFIG_COMMON_CLK_CDCE706=y
CONFIG_COMMON_CLK_TPS68470=y
CONFIG_COMMON_CLK_CDCE925=y
CONFIG_COMMON_CLK_CS2000_CP=y
CONFIG_COMMON_CLK_S2MPS11=y
CONFIG_CLK_TWL6040=y
CONFIG_COMMON_CLK_AXI_CLKGEN=y
CONFIG_COMMON_CLK_LOCHNAGAR=y
CONFIG_COMMON_CLK_PALMAS=y
CONFIG_COMMON_CLK_PWM=y
CONFIG_COMMON_CLK_RS9_PCIE=y
CONFIG_COMMON_CLK_VC5=y
CONFIG_COMMON_CLK_BD718XX=y
CONFIG_COMMON_CLK_FIXED_MMIO=y
CONFIG_CLK_LGM_CGU=y
CONFIG_XILINX_VCU=y
CONFIG_CLK_KUNIT_TEST=y
CONFIG_CLK_GATE_KUNIT_TEST=y
CONFIG_HWSPINLOCK=y

#
# Clock Source drivers
#
CONFIG_TIMER_OF=y
CONFIG_TIMER_PROBE=y
CONFIG_CLKEVT_I8253=y
CONFIG_I8253_LOCK=y
CONFIG_CLKBLD_I8253=y
CONFIG_DW_APB_TIMER=y
CONFIG_MICROCHIP_PIT64B=y
# end of Clock Source drivers

CONFIG_MAILBOX=y
CONFIG_PLATFORM_MHU=y
CONFIG_PCC=y
CONFIG_ALTERA_MBOX=y
CONFIG_MAILBOX_TEST=y
CONFIG_IOMMU_IOVA=y
CONFIG_IOASID=y
CONFIG_IOMMU_API=y
CONFIG_IOMMU_SUPPORT=y

#
# Generic IOMMU Pagetable Support
#
CONFIG_IOMMU_IO_PGTABLE=y
# end of Generic IOMMU Pagetable Support

CONFIG_IOMMU_DEBUGFS=y
# CONFIG_IOMMU_DEFAULT_DMA_STRICT is not set
CONFIG_IOMMU_DEFAULT_DMA_LAZY=y
# CONFIG_IOMMU_DEFAULT_PASSTHROUGH is not set
CONFIG_OF_IOMMU=y
CONFIG_IOMMU_DMA=y
CONFIG_IOMMU_SVA=y
CONFIG_AMD_IOMMU=y
CONFIG_AMD_IOMMU_V2=y
CONFIG_AMD_IOMMU_DEBUGFS=y
CONFIG_DMAR_TABLE=y
CONFIG_DMAR_PERF=y
CONFIG_DMAR_DEBUG=y
CONFIG_INTEL_IOMMU=y
CONFIG_INTEL_IOMMU_DEBUGFS=y
CONFIG_INTEL_IOMMU_SVM=y
CONFIG_INTEL_IOMMU_DEFAULT_ON=y
CONFIG_INTEL_IOMMU_FLOPPY_WA=y
CONFIG_INTEL_IOMMU_SCALABLE_MODE_DEFAULT_ON=y
CONFIG_IRQ_REMAP=y
CONFIG_HYPERV_IOMMU=y
CONFIG_VIRTIO_IOMMU=y

#
# Remoteproc drivers
#
CONFIG_REMOTEPROC=y
CONFIG_REMOTEPROC_CDEV=y
# end of Remoteproc drivers

#
# Rpmsg drivers
#
CONFIG_RPMSG=y
CONFIG_RPMSG_CHAR=y
CONFIG_RPMSG_CTRL=y
CONFIG_RPMSG_NS=y
CONFIG_RPMSG_QCOM_GLINK=y
CONFIG_RPMSG_QCOM_GLINK_RPM=y
CONFIG_RPMSG_VIRTIO=y
# end of Rpmsg drivers

CONFIG_SOUNDWIRE=y

#
# SoundWire Devices
#
CONFIG_SOUNDWIRE_CADENCE=y
CONFIG_SOUNDWIRE_INTEL=y
CONFIG_SOUNDWIRE_QCOM=y
CONFIG_SOUNDWIRE_GENERIC_ALLOCATION=y

#
# SOC (System On Chip) specific Drivers
#

#
# Amlogic SoC drivers
#
# end of Amlogic SoC drivers

#
# Broadcom SoC drivers
#
# end of Broadcom SoC drivers

#
# NXP/Freescale QorIQ SoC drivers
#
# end of NXP/Freescale QorIQ SoC drivers

#
# fujitsu SoC drivers
#
# end of fujitsu SoC drivers

#
# i.MX SoC drivers
#
# end of i.MX SoC drivers

#
# Enable LiteX SoC Builder specific drivers
#
CONFIG_LITEX=y
CONFIG_LITEX_SOC_CONTROLLER=y
# end of Enable LiteX SoC Builder specific drivers

#
# Qualcomm SoC drivers
#
CONFIG_QCOM_QMI_HELPERS=y
# end of Qualcomm SoC drivers

CONFIG_SOC_TI=y

#
# Xilinx SoC drivers
#
# end of Xilinx SoC drivers
# end of SOC (System On Chip) specific Drivers

CONFIG_PM_DEVFREQ=y

#
# DEVFREQ Governors
#
CONFIG_DEVFREQ_GOV_SIMPLE_ONDEMAND=y
CONFIG_DEVFREQ_GOV_PERFORMANCE=y
CONFIG_DEVFREQ_GOV_POWERSAVE=y
CONFIG_DEVFREQ_GOV_USERSPACE=y
CONFIG_DEVFREQ_GOV_PASSIVE=y

#
# DEVFREQ Drivers
#
CONFIG_PM_DEVFREQ_EVENT=y
CONFIG_EXTCON=y

#
# Extcon Device Drivers
#
CONFIG_EXTCON_ADC_JACK=y
CONFIG_EXTCON_AXP288=y
CONFIG_EXTCON_FSA9480=y
CONFIG_EXTCON_GPIO=y
CONFIG_EXTCON_INTEL_INT3496=y
CONFIG_EXTCON_INTEL_CHT_WC=y
CONFIG_EXTCON_INTEL_MRFLD=y
CONFIG_EXTCON_MAX14577=y
CONFIG_EXTCON_MAX3355=y
CONFIG_EXTCON_MAX77693=y
CONFIG_EXTCON_MAX77843=y
CONFIG_EXTCON_MAX8997=y
CONFIG_EXTCON_PALMAS=y
CONFIG_EXTCON_PTN5150=y
CONFIG_EXTCON_RT8973A=y
CONFIG_EXTCON_SM5502=y
CONFIG_EXTCON_USB_GPIO=y
CONFIG_EXTCON_USBC_CROS_EC=y
CONFIG_EXTCON_USBC_TUSB320=y
CONFIG_MEMORY=y
CONFIG_FPGA_DFL_EMIF=y
CONFIG_IIO=y
CONFIG_IIO_BUFFER=y
CONFIG_IIO_BUFFER_CB=y
CONFIG_IIO_BUFFER_DMA=y
CONFIG_IIO_BUFFER_DMAENGINE=y
CONFIG_IIO_BUFFER_HW_CONSUMER=y
CONFIG_IIO_KFIFO_BUF=y
CONFIG_IIO_TRIGGERED_BUFFER=y
CONFIG_IIO_CONFIGFS=y
CONFIG_IIO_TRIGGER=y
CONFIG_IIO_CONSUMERS_PER_TRIGGER=2
CONFIG_IIO_SW_DEVICE=y
CONFIG_IIO_SW_TRIGGER=y
CONFIG_IIO_TRIGGERED_EVENT=y

#
# Accelerometers
#
CONFIG_ADIS16201=y
CONFIG_ADIS16209=y
CONFIG_ADXL313=y
CONFIG_ADXL313_I2C=y
CONFIG_ADXL313_SPI=y
CONFIG_ADXL355=y
CONFIG_ADXL355_I2C=y
CONFIG_ADXL355_SPI=y
CONFIG_ADXL367=y
CONFIG_ADXL367_SPI=y
CONFIG_ADXL367_I2C=y
CONFIG_ADXL372=y
CONFIG_ADXL372_SPI=y
CONFIG_ADXL372_I2C=y
CONFIG_BMA220=y
CONFIG_BMA400=y
CONFIG_BMA400_I2C=y
CONFIG_BMA400_SPI=y
CONFIG_BMC150_ACCEL=y
CONFIG_BMC150_ACCEL_I2C=y
CONFIG_BMC150_ACCEL_SPI=y
CONFIG_BMI088_ACCEL=y
CONFIG_BMI088_ACCEL_SPI=y
CONFIG_DA280=y
CONFIG_DA311=y
CONFIG_DMARD06=y
CONFIG_DMARD09=y
CONFIG_DMARD10=y
CONFIG_FXLS8962AF=y
CONFIG_FXLS8962AF_I2C=y
CONFIG_FXLS8962AF_SPI=y
CONFIG_HID_SENSOR_ACCEL_3D=y
CONFIG_IIO_CROS_EC_ACCEL_LEGACY=y
CONFIG_KXSD9=y
CONFIG_KXSD9_SPI=y
CONFIG_KXSD9_I2C=y
CONFIG_KXCJK1013=y
CONFIG_MC3230=y
CONFIG_MMA7455=y
CONFIG_MMA7455_I2C=y
CONFIG_MMA7455_SPI=y
CONFIG_MMA7660=y
CONFIG_MMA8452=y
CONFIG_MMA9551_CORE=y
CONFIG_MMA9551=y
CONFIG_MMA9553=y
CONFIG_MXC4005=y
CONFIG_MXC6255=y
CONFIG_SCA3000=y
CONFIG_SCA3300=y
CONFIG_STK8312=y
CONFIG_STK8BA50=y
# end of Accelerometers

#
# Analog to digital converters
#
CONFIG_AD_SIGMA_DELTA=y
CONFIG_AD7091R5=y
CONFIG_AD7124=y
CONFIG_AD7192=y
CONFIG_AD7266=y
CONFIG_AD7280=y
CONFIG_AD7291=y
CONFIG_AD7292=y
CONFIG_AD7298=y
CONFIG_AD7476=y
CONFIG_AD7606=y
CONFIG_AD7606_IFACE_PARALLEL=y
CONFIG_AD7606_IFACE_SPI=y
CONFIG_AD7766=y
CONFIG_AD7768_1=y
CONFIG_AD7780=y
CONFIG_AD7791=y
CONFIG_AD7793=y
CONFIG_AD7887=y
CONFIG_AD7923=y
CONFIG_AD7949=y
CONFIG_AD799X=y
CONFIG_AD9467=y
CONFIG_ADI_AXI_ADC=y
CONFIG_AXP20X_ADC=y
CONFIG_AXP288_ADC=y
CONFIG_CC10001_ADC=y
CONFIG_CPCAP_ADC=y
CONFIG_DA9150_GPADC=y
CONFIG_DLN2_ADC=y
CONFIG_ENVELOPE_DETECTOR=y
CONFIG_HI8435=y
CONFIG_HX711=y
CONFIG_INTEL_MRFLD_ADC=y
CONFIG_LP8788_ADC=y
CONFIG_LTC2471=y
CONFIG_LTC2485=y
CONFIG_LTC2496=y
CONFIG_LTC2497=y
CONFIG_MAX1027=y
CONFIG_MAX11100=y
CONFIG_MAX1118=y
CONFIG_MAX1241=y
CONFIG_MAX1363=y
CONFIG_MAX9611=y
CONFIG_MCP320X=y
CONFIG_MCP3422=y
CONFIG_MCP3911=y
CONFIG_MEDIATEK_MT6360_ADC=y
CONFIG_MEN_Z188_ADC=y
CONFIG_MP2629_ADC=y
CONFIG_NAU7802=y
CONFIG_PALMAS_GPADC=y
CONFIG_QCOM_VADC_COMMON=y
CONFIG_QCOM_SPMI_IADC=y
CONFIG_QCOM_SPMI_VADC=y
CONFIG_QCOM_SPMI_ADC5=y
CONFIG_RN5T618_ADC=y
CONFIG_SD_ADC_MODULATOR=y
CONFIG_STMPE_ADC=y
CONFIG_STX104=y
CONFIG_TI_ADC081C=y
CONFIG_TI_ADC0832=y
CONFIG_TI_ADC084S021=y
CONFIG_TI_ADC12138=y
CONFIG_TI_ADC108S102=y
CONFIG_TI_ADC128S052=y
CONFIG_TI_ADC161S626=y
CONFIG_TI_ADS1015=y
CONFIG_TI_ADS7950=y
CONFIG_TI_ADS8344=y
CONFIG_TI_ADS8688=y
CONFIG_TI_ADS124S08=y
CONFIG_TI_ADS131E08=y
CONFIG_TI_AM335X_ADC=y
CONFIG_TI_TLC4541=y
CONFIG_TI_TSC2046=y
CONFIG_TWL4030_MADC=y
CONFIG_TWL6030_GPADC=y
CONFIG_VF610_ADC=y
CONFIG_VIPERBOARD_ADC=y
CONFIG_XILINX_XADC=y
# end of Analog to digital converters

#
# Analog to digital and digital to analog converters
#
CONFIG_AD74413R=y
# end of Analog to digital and digital to analog converters

#
# Analog Front Ends
#
CONFIG_IIO_RESCALE=y
# end of Analog Front Ends

#
# Amplifiers
#
CONFIG_AD8366=y
CONFIG_ADA4250=y
CONFIG_HMC425=y
# end of Amplifiers

#
# Capacitance to digital converters
#
CONFIG_AD7150=y
# end of Capacitance to digital converters

#
# Chemical Sensors
#
CONFIG_ATLAS_PH_SENSOR=y
CONFIG_ATLAS_EZO_SENSOR=y
CONFIG_BME680=y
CONFIG_BME680_I2C=y
CONFIG_BME680_SPI=y
CONFIG_CCS811=y
CONFIG_IAQCORE=y
CONFIG_PMS7003=y
CONFIG_SCD30_CORE=y
CONFIG_SCD30_I2C=y
CONFIG_SCD30_SERIAL=y
CONFIG_SCD4X=y
CONFIG_SENSIRION_SGP30=y
CONFIG_SENSIRION_SGP40=y
CONFIG_SPS30=y
CONFIG_SPS30_I2C=y
CONFIG_SPS30_SERIAL=y
CONFIG_SENSEAIR_SUNRISE_CO2=y
CONFIG_VZ89X=y
# end of Chemical Sensors

CONFIG_IIO_CROS_EC_SENSORS_CORE=y
CONFIG_IIO_CROS_EC_SENSORS=y
CONFIG_IIO_CROS_EC_SENSORS_LID_ANGLE=y

#
# Hid Sensor IIO Common
#
CONFIG_HID_SENSOR_IIO_COMMON=y
CONFIG_HID_SENSOR_IIO_TRIGGER=y
# end of Hid Sensor IIO Common

CONFIG_IIO_MS_SENSORS_I2C=y

#
# IIO SCMI Sensors
#
# end of IIO SCMI Sensors

#
# SSP Sensor Common
#
CONFIG_IIO_SSP_SENSORS_COMMONS=y
CONFIG_IIO_SSP_SENSORHUB=y
# end of SSP Sensor Common

CONFIG_IIO_ST_SENSORS_I2C=y
CONFIG_IIO_ST_SENSORS_SPI=y
CONFIG_IIO_ST_SENSORS_CORE=y

#
# Digital to analog converters
#
CONFIG_AD3552R=y
CONFIG_AD5064=y
CONFIG_AD5360=y
CONFIG_AD5380=y
CONFIG_AD5421=y
CONFIG_AD5446=y
CONFIG_AD5449=y
CONFIG_AD5592R_BASE=y
CONFIG_AD5592R=y
CONFIG_AD5593R=y
CONFIG_AD5504=y
CONFIG_AD5624R_SPI=y
CONFIG_LTC2688=y
CONFIG_AD5686=y
CONFIG_AD5686_SPI=y
CONFIG_AD5696_I2C=y
CONFIG_AD5755=y
CONFIG_AD5758=y
CONFIG_AD5761=y
CONFIG_AD5764=y
CONFIG_AD5766=y
CONFIG_AD5770R=y
CONFIG_AD5791=y
CONFIG_AD7293=y
CONFIG_AD7303=y
CONFIG_AD8801=y
CONFIG_CIO_DAC=y
CONFIG_DPOT_DAC=y
CONFIG_DS4424=y
CONFIG_LTC1660=y
CONFIG_LTC2632=y
CONFIG_M62332=y
CONFIG_MAX517=y
CONFIG_MAX5821=y
CONFIG_MCP4725=y
CONFIG_MCP4922=y
CONFIG_TI_DAC082S085=y
CONFIG_TI_DAC5571=y
CONFIG_TI_DAC7311=y
CONFIG_TI_DAC7612=y
CONFIG_VF610_DAC=y
# end of Digital to analog converters

#
# IIO dummy driver
#
CONFIG_IIO_DUMMY_EVGEN=y
CONFIG_IIO_SIMPLE_DUMMY=y
CONFIG_IIO_SIMPLE_DUMMY_EVENTS=y
CONFIG_IIO_SIMPLE_DUMMY_BUFFER=y
# end of IIO dummy driver

#
# Filters
#
CONFIG_ADMV8818=y
# end of Filters

#
# Frequency Synthesizers DDS/PLL
#

#
# Clock Generator/Distribution
#
CONFIG_AD9523=y
# end of Clock Generator/Distribution

#
# Phase-Locked Loop (PLL) frequency synthesizers
#
CONFIG_ADF4350=y
CONFIG_ADF4371=y
CONFIG_ADMV1013=y
CONFIG_ADMV1014=y
CONFIG_ADMV4420=y
CONFIG_ADRF6780=y
# end of Phase-Locked Loop (PLL) frequency synthesizers
# end of Frequency Synthesizers DDS/PLL

#
# Digital gyroscope sensors
#
CONFIG_ADIS16080=y
CONFIG_ADIS16130=y
CONFIG_ADIS16136=y
CONFIG_ADIS16260=y
CONFIG_ADXRS290=y
CONFIG_ADXRS450=y
CONFIG_BMG160=y
CONFIG_BMG160_I2C=y
CONFIG_BMG160_SPI=y
CONFIG_FXAS21002C=y
CONFIG_FXAS21002C_I2C=y
CONFIG_FXAS21002C_SPI=y
CONFIG_HID_SENSOR_GYRO_3D=y
CONFIG_MPU3050=y
CONFIG_MPU3050_I2C=y
CONFIG_IIO_ST_GYRO_3AXIS=y
CONFIG_IIO_ST_GYRO_I2C_3AXIS=y
CONFIG_IIO_ST_GYRO_SPI_3AXIS=y
CONFIG_ITG3200=y
# end of Digital gyroscope sensors

#
# Health Sensors
#

#
# Heart Rate Monitors
#
CONFIG_AFE4403=y
CONFIG_AFE4404=y
CONFIG_MAX30100=y
CONFIG_MAX30102=y
# end of Heart Rate Monitors
# end of Health Sensors

#
# Humidity sensors
#
CONFIG_AM2315=y
CONFIG_DHT11=y
CONFIG_HDC100X=y
CONFIG_HDC2010=y
CONFIG_HID_SENSOR_HUMIDITY=y
CONFIG_HTS221=y
CONFIG_HTS221_I2C=y
CONFIG_HTS221_SPI=y
CONFIG_HTU21=y
CONFIG_SI7005=y
CONFIG_SI7020=y
# end of Humidity sensors

#
# Inertial measurement units
#
CONFIG_ADIS16400=y
CONFIG_ADIS16460=y
CONFIG_ADIS16475=y
CONFIG_ADIS16480=y
CONFIG_BMI160=y
CONFIG_BMI160_I2C=y
CONFIG_BMI160_SPI=y
CONFIG_FXOS8700=y
CONFIG_FXOS8700_I2C=y
CONFIG_FXOS8700_SPI=y
CONFIG_KMX61=y
CONFIG_INV_ICM42600=y
CONFIG_INV_ICM42600_I2C=y
CONFIG_INV_ICM42600_SPI=y
CONFIG_INV_MPU6050_IIO=y
CONFIG_INV_MPU6050_I2C=y
CONFIG_INV_MPU6050_SPI=y
CONFIG_IIO_ST_LSM6DSX=y
CONFIG_IIO_ST_LSM6DSX_I2C=y
CONFIG_IIO_ST_LSM6DSX_SPI=y
CONFIG_IIO_ST_LSM6DSX_I3C=y
# end of Inertial measurement units

CONFIG_IIO_ADIS_LIB=y
CONFIG_IIO_ADIS_LIB_BUFFER=y

#
# Light sensors
#
CONFIG_ACPI_ALS=y
CONFIG_ADJD_S311=y
CONFIG_ADUX1020=y
CONFIG_AL3010=y
CONFIG_AL3320A=y
CONFIG_APDS9300=y
CONFIG_APDS9960=y
CONFIG_AS73211=y
CONFIG_BH1750=y
CONFIG_BH1780=y
CONFIG_CM32181=y
CONFIG_CM3232=y
CONFIG_CM3323=y
CONFIG_CM3605=y
CONFIG_CM36651=y
CONFIG_IIO_CROS_EC_LIGHT_PROX=y
CONFIG_GP2AP002=y
CONFIG_GP2AP020A00F=y
CONFIG_IQS621_ALS=y
CONFIG_SENSORS_ISL29018=y
CONFIG_SENSORS_ISL29028=y
CONFIG_ISL29125=y
CONFIG_HID_SENSOR_ALS=y
CONFIG_HID_SENSOR_PROX=y
CONFIG_JSA1212=y
CONFIG_RPR0521=y
CONFIG_SENSORS_LM3533=y
CONFIG_LTR501=y
CONFIG_LV0104CS=y
CONFIG_MAX44000=y
CONFIG_MAX44009=y
CONFIG_NOA1305=y
CONFIG_OPT3001=y
CONFIG_PA12203001=y
CONFIG_SI1133=y
CONFIG_SI1145=y
CONFIG_STK3310=y
CONFIG_ST_UVIS25=y
CONFIG_ST_UVIS25_I2C=y
CONFIG_ST_UVIS25_SPI=y
CONFIG_TCS3414=y
CONFIG_TCS3472=y
CONFIG_SENSORS_TSL2563=y
CONFIG_TSL2583=y
CONFIG_TSL2591=y
CONFIG_TSL2772=y
CONFIG_TSL4531=y
CONFIG_US5182D=y
CONFIG_VCNL4000=y
CONFIG_VCNL4035=y
CONFIG_VEML6030=y
CONFIG_VEML6070=y
CONFIG_VL6180=y
CONFIG_ZOPT2201=y
# end of Light sensors

#
# Magnetometer sensors
#
CONFIG_AK8974=y
CONFIG_AK8975=y
CONFIG_AK09911=y
CONFIG_BMC150_MAGN=y
CONFIG_BMC150_MAGN_I2C=y
CONFIG_BMC150_MAGN_SPI=y
CONFIG_MAG3110=y
CONFIG_HID_SENSOR_MAGNETOMETER_3D=y
CONFIG_MMC35240=y
CONFIG_IIO_ST_MAGN_3AXIS=y
CONFIG_IIO_ST_MAGN_I2C_3AXIS=y
CONFIG_IIO_ST_MAGN_SPI_3AXIS=y
CONFIG_SENSORS_HMC5843=y
CONFIG_SENSORS_HMC5843_I2C=y
CONFIG_SENSORS_HMC5843_SPI=y
CONFIG_SENSORS_RM3100=y
CONFIG_SENSORS_RM3100_I2C=y
CONFIG_SENSORS_RM3100_SPI=y
CONFIG_YAMAHA_YAS530=y
# end of Magnetometer sensors

#
# Multiplexers
#
CONFIG_IIO_MUX=y
# end of Multiplexers

#
# Inclinometer sensors
#
CONFIG_HID_SENSOR_INCLINOMETER_3D=y
CONFIG_HID_SENSOR_DEVICE_ROTATION=y
# end of Inclinometer sensors

CONFIG_IIO_RESCALE_KUNIT_TEST=y
CONFIG_IIO_FORMAT_KUNIT_TEST=y

#
# Triggers - standalone
#
CONFIG_IIO_HRTIMER_TRIGGER=y
CONFIG_IIO_INTERRUPT_TRIGGER=y
CONFIG_IIO_TIGHTLOOP_TRIGGER=y
CONFIG_IIO_SYSFS_TRIGGER=y
# end of Triggers - standalone

#
# Linear and angular position sensors
#
CONFIG_IQS624_POS=y
CONFIG_HID_SENSOR_CUSTOM_INTEL_HINGE=y
# end of Linear and angular position sensors

#
# Digital potentiometers
#
CONFIG_AD5110=y
CONFIG_AD5272=y
CONFIG_DS1803=y
CONFIG_MAX5432=y
CONFIG_MAX5481=y
CONFIG_MAX5487=y
CONFIG_MCP4018=y
CONFIG_MCP4131=y
CONFIG_MCP4531=y
CONFIG_MCP41010=y
CONFIG_TPL0102=y
# end of Digital potentiometers

#
# Digital potentiostats
#
CONFIG_LMP91000=y
# end of Digital potentiostats

#
# Pressure sensors
#
CONFIG_ABP060MG=y
CONFIG_BMP280=y
CONFIG_BMP280_I2C=y
CONFIG_BMP280_SPI=y
CONFIG_IIO_CROS_EC_BARO=y
CONFIG_DLHL60D=y
CONFIG_DPS310=y
CONFIG_HID_SENSOR_PRESS=y
CONFIG_HP03=y
CONFIG_ICP10100=y
CONFIG_MPL115=y
CONFIG_MPL115_I2C=y
CONFIG_MPL115_SPI=y
CONFIG_MPL3115=y
CONFIG_MS5611=y
CONFIG_MS5611_I2C=y
CONFIG_MS5611_SPI=y
CONFIG_MS5637=y
CONFIG_IIO_ST_PRESS=y
CONFIG_IIO_ST_PRESS_I2C=y
CONFIG_IIO_ST_PRESS_SPI=y
CONFIG_T5403=y
CONFIG_HP206C=y
CONFIG_ZPA2326=y
CONFIG_ZPA2326_I2C=y
CONFIG_ZPA2326_SPI=y
# end of Pressure sensors

#
# Lightning sensors
#
CONFIG_AS3935=y
# end of Lightning sensors

#
# Proximity and distance sensors
#
CONFIG_CROS_EC_MKBP_PROXIMITY=y
CONFIG_ISL29501=y
CONFIG_LIDAR_LITE_V2=y
CONFIG_MB1232=y
CONFIG_PING=y
CONFIG_RFD77402=y
CONFIG_SRF04=y
CONFIG_SX_COMMON=y
CONFIG_SX9310=y
CONFIG_SX9324=y
CONFIG_SX9360=y
CONFIG_SX9500=y
CONFIG_SRF08=y
CONFIG_VCNL3020=y
CONFIG_VL53L0X_I2C=y
# end of Proximity and distance sensors

#
# Resolver to digital converters
#
CONFIG_AD2S90=y
CONFIG_AD2S1200=y
# end of Resolver to digital converters

#
# Temperature sensors
#
CONFIG_IQS620AT_TEMP=y
CONFIG_LTC2983=y
CONFIG_MAXIM_THERMOCOUPLE=y
CONFIG_HID_SENSOR_TEMP=y
CONFIG_MLX90614=y
CONFIG_MLX90632=y
CONFIG_TMP006=y
CONFIG_TMP007=y
CONFIG_TMP117=y
CONFIG_TSYS01=y
CONFIG_TSYS02D=y
CONFIG_MAX31856=y
CONFIG_MAX31865=y
# end of Temperature sensors

CONFIG_NTB=y
CONFIG_NTB_MSI=y
CONFIG_NTB_AMD=y
CONFIG_NTB_IDT=y
CONFIG_NTB_INTEL=y
CONFIG_NTB_EPF=m
CONFIG_NTB_SWITCHTEC=y
CONFIG_NTB_PINGPONG=y
CONFIG_NTB_TOOL=y
CONFIG_NTB_PERF=y
CONFIG_NTB_MSI_TEST=y
CONFIG_NTB_TRANSPORT=y
CONFIG_PWM=y
CONFIG_PWM_SYSFS=y
CONFIG_PWM_DEBUG=y
CONFIG_PWM_ATMEL_HLCDC_PWM=y
CONFIG_PWM_ATMEL_TCB=y
CONFIG_PWM_CLK=y
CONFIG_PWM_CRC=y
CONFIG_PWM_CROS_EC=y
CONFIG_PWM_DWC=y
CONFIG_PWM_FSL_FTM=y
CONFIG_PWM_INTEL_LGM=y
CONFIG_PWM_IQS620A=y
CONFIG_PWM_LP3943=y
CONFIG_PWM_LPSS=y
CONFIG_PWM_LPSS_PCI=y
CONFIG_PWM_LPSS_PLATFORM=y
CONFIG_PWM_NTXEC=y
CONFIG_PWM_PCA9685=y
CONFIG_PWM_STMPE=y
CONFIG_PWM_TWL=y
CONFIG_PWM_TWL_LED=y
CONFIG_PWM_XILINX=y

#
# IRQ chip support
#
CONFIG_IRQCHIP=y
CONFIG_AL_FIC=y
CONFIG_MADERA_IRQ=y
CONFIG_XILINX_INTC=y
# end of IRQ chip support

CONFIG_IPACK_BUS=y
CONFIG_BOARD_TPCI200=y
CONFIG_SERIAL_IPOCTAL=y
CONFIG_RESET_CONTROLLER=y
CONFIG_RESET_INTEL_GW=y
CONFIG_RESET_SIMPLE=y
CONFIG_RESET_TI_SYSCON=y
CONFIG_RESET_TI_TPS380X=y

#
# PHY Subsystem
#
CONFIG_GENERIC_PHY=y
CONFIG_GENERIC_PHY_MIPI_DPHY=y
CONFIG_USB_LGM_PHY=y
CONFIG_PHY_CAN_TRANSCEIVER=y

#
# PHY drivers for Broadcom platforms
#
CONFIG_BCM_KONA_USB2_PHY=y
# end of PHY drivers for Broadcom platforms

CONFIG_PHY_CADENCE_TORRENT=y
CONFIG_PHY_CADENCE_DPHY=y
CONFIG_PHY_CADENCE_DPHY_RX=y
CONFIG_PHY_CADENCE_SIERRA=y
CONFIG_PHY_CADENCE_SALVO=y
CONFIG_PHY_PXA_28NM_HSIC=y
CONFIG_PHY_PXA_28NM_USB2=y
CONFIG_PHY_LAN966X_SERDES=y
CONFIG_PHY_CPCAP_USB=y
CONFIG_PHY_MAPPHONE_MDM6600=y
CONFIG_PHY_OCELOT_SERDES=y
CONFIG_PHY_QCOM_USB_HS=y
CONFIG_PHY_QCOM_USB_HSIC=y
CONFIG_PHY_SAMSUNG_USB2=y
CONFIG_PHY_TUSB1210=y
CONFIG_PHY_INTEL_LGM_COMBO=y
CONFIG_PHY_INTEL_LGM_EMMC=y
# end of PHY Subsystem

CONFIG_POWERCAP=y
CONFIG_INTEL_RAPL_CORE=y
CONFIG_INTEL_RAPL=y
CONFIG_IDLE_INJECT=y
CONFIG_DTPM=y
CONFIG_DTPM_CPU=y
CONFIG_DTPM_DEVFREQ=y
CONFIG_MCB=y
CONFIG_MCB_PCI=y
CONFIG_MCB_LPC=y

#
# Performance monitor support
#
# end of Performance monitor support

CONFIG_RAS=y
CONFIG_RAS_CEC=y
CONFIG_RAS_CEC_DEBUG=y
CONFIG_USB4=y
CONFIG_USB4_DEBUGFS_WRITE=y
CONFIG_USB4_KUNIT_TEST=y
CONFIG_USB4_DMA_TEST=y

#
# Android
#
CONFIG_ANDROID_BINDER_IPC=y
CONFIG_ANDROID_BINDERFS=y
CONFIG_ANDROID_BINDER_DEVICES="binder,hwbinder,vndbinder"
CONFIG_ANDROID_BINDER_IPC_SELFTEST=y
# end of Android

CONFIG_LIBNVDIMM=y
CONFIG_BLK_DEV_PMEM=y
CONFIG_ND_CLAIM=y
CONFIG_ND_BTT=y
CONFIG_BTT=y
CONFIG_ND_PFN=y
CONFIG_NVDIMM_PFN=y
CONFIG_NVDIMM_DAX=y
CONFIG_OF_PMEM=y
CONFIG_NVDIMM_KEYS=y
CONFIG_DAX=y
CONFIG_DEV_DAX=y
CONFIG_DEV_DAX_PMEM=y
CONFIG_DEV_DAX_HMEM=y
CONFIG_DEV_DAX_HMEM_DEVICES=y
CONFIG_DEV_DAX_KMEM=y
CONFIG_NVMEM=y
CONFIG_NVMEM_SYSFS=y
CONFIG_NVMEM_SPMI_SDAM=y
CONFIG_RAVE_SP_EEPROM=y
CONFIG_NVMEM_RMEM=y

#
# HW tracing support
#
CONFIG_STM=y
CONFIG_STM_PROTO_BASIC=y
CONFIG_STM_PROTO_SYS_T=y
CONFIG_STM_DUMMY=y
CONFIG_STM_SOURCE_CONSOLE=y
CONFIG_STM_SOURCE_HEARTBEAT=y
CONFIG_STM_SOURCE_FTRACE=y
CONFIG_INTEL_TH=y
CONFIG_INTEL_TH_PCI=y
CONFIG_INTEL_TH_ACPI=y
CONFIG_INTEL_TH_GTH=y
CONFIG_INTEL_TH_STH=y
CONFIG_INTEL_TH_MSU=y
CONFIG_INTEL_TH_PTI=y
CONFIG_INTEL_TH_DEBUG=y
# end of HW tracing support

CONFIG_FPGA=y
CONFIG_ALTERA_PR_IP_CORE=y
CONFIG_ALTERA_PR_IP_CORE_PLAT=y
CONFIG_FPGA_MGR_ALTERA_PS_SPI=y
CONFIG_FPGA_MGR_ALTERA_CVP=y
CONFIG_FPGA_MGR_XILINX_SPI=y
CONFIG_FPGA_MGR_ICE40_SPI=y
CONFIG_FPGA_MGR_MACHXO2_SPI=y
CONFIG_FPGA_BRIDGE=y
CONFIG_ALTERA_FREEZE_BRIDGE=y
CONFIG_XILINX_PR_DECOUPLER=y
CONFIG_FPGA_REGION=y
CONFIG_OF_FPGA_REGION=y
CONFIG_FPGA_DFL=y
CONFIG_FPGA_DFL_FME=y
CONFIG_FPGA_DFL_FME_MGR=y
CONFIG_FPGA_DFL_FME_BRIDGE=y
CONFIG_FPGA_DFL_FME_REGION=y
CONFIG_FPGA_DFL_AFU=y
CONFIG_FPGA_DFL_NIOS_INTEL_PAC_N3000=y
CONFIG_FPGA_DFL_PCI=y
CONFIG_FPGA_M10_BMC_SEC_UPDATE=y
CONFIG_FPGA_MGR_MICROCHIP_SPI=y
CONFIG_FSI=y
CONFIG_FSI_NEW_DEV_NODE=y
CONFIG_FSI_MASTER_GPIO=y
CONFIG_FSI_MASTER_HUB=y
CONFIG_FSI_MASTER_ASPEED=y
CONFIG_FSI_SCOM=y
CONFIG_FSI_SBEFIFO=y
CONFIG_FSI_OCC=y
CONFIG_TEE=y
CONFIG_AMDTEE=y
CONFIG_MULTIPLEXER=y

#
# Multiplexer drivers
#
CONFIG_MUX_ADG792A=y
CONFIG_MUX_ADGS1408=y
CONFIG_MUX_GPIO=y
CONFIG_MUX_MMIO=y
# end of Multiplexer drivers

CONFIG_PM_OPP=y
CONFIG_SIOX=y
CONFIG_SIOX_BUS_GPIO=y
CONFIG_SLIMBUS=y
CONFIG_SLIM_QCOM_CTRL=y
CONFIG_INTERCONNECT=y
CONFIG_COUNTER=y
CONFIG_104_QUAD_8=y
CONFIG_INTERRUPT_CNT=y
CONFIG_FTM_QUADDEC=y
CONFIG_MICROCHIP_TCB_CAPTURE=y
CONFIG_INTEL_QEP=y
CONFIG_MOST=y
CONFIG_MOST_USB_HDM=y
CONFIG_MOST_CDEV=y
CONFIG_MOST_SND=y
CONFIG_PECI=y
CONFIG_PECI_CPU=y
CONFIG_HTE=y
# end of Device Drivers

#
# File systems
#
CONFIG_DCACHE_WORD_ACCESS=y
CONFIG_VALIDATE_FS_PARSER=y
CONFIG_FS_IOMAP=y
CONFIG_EXT2_FS=y
CONFIG_EXT2_FS_XATTR=y
CONFIG_EXT2_FS_POSIX_ACL=y
CONFIG_EXT2_FS_SECURITY=y
CONFIG_EXT3_FS=y
CONFIG_EXT3_FS_POSIX_ACL=y
CONFIG_EXT3_FS_SECURITY=y
CONFIG_EXT4_FS=y
CONFIG_EXT4_FS_POSIX_ACL=y
CONFIG_EXT4_FS_SECURITY=y
CONFIG_EXT4_DEBUG=y
CONFIG_EXT4_KUNIT_TESTS=y
CONFIG_JBD2=y
CONFIG_JBD2_DEBUG=y
CONFIG_FS_MBCACHE=y
CONFIG_REISERFS_FS=y
CONFIG_REISERFS_CHECK=y
CONFIG_REISERFS_PROC_INFO=y
CONFIG_REISERFS_FS_XATTR=y
CONFIG_REISERFS_FS_POSIX_ACL=y
CONFIG_REISERFS_FS_SECURITY=y
CONFIG_JFS_FS=y
CONFIG_JFS_POSIX_ACL=y
CONFIG_JFS_SECURITY=y
CONFIG_JFS_DEBUG=y
CONFIG_JFS_STATISTICS=y
CONFIG_XFS_FS=y
CONFIG_XFS_SUPPORT_V4=y
CONFIG_XFS_QUOTA=y
CONFIG_XFS_POSIX_ACL=y
CONFIG_XFS_RT=y
CONFIG_XFS_ONLINE_SCRUB=y
CONFIG_XFS_ONLINE_REPAIR=y
CONFIG_XFS_DEBUG=y
CONFIG_XFS_ASSERT_FATAL=y
CONFIG_GFS2_FS=y
CONFIG_GFS2_FS_LOCKING_DLM=y
CONFIG_OCFS2_FS=y
CONFIG_OCFS2_FS_O2CB=y
CONFIG_OCFS2_FS_USERSPACE_CLUSTER=y
CONFIG_OCFS2_FS_STATS=y
CONFIG_OCFS2_DEBUG_MASKLOG=y
CONFIG_OCFS2_DEBUG_FS=y
CONFIG_BTRFS_FS=y
CONFIG_BTRFS_FS_POSIX_ACL=y
CONFIG_BTRFS_FS_CHECK_INTEGRITY=y
CONFIG_BTRFS_FS_RUN_SANITY_TESTS=y
CONFIG_BTRFS_DEBUG=y
CONFIG_BTRFS_ASSERT=y
CONFIG_BTRFS_FS_REF_VERIFY=y
CONFIG_NILFS2_FS=y
CONFIG_F2FS_FS=y
CONFIG_F2FS_STAT_FS=y
CONFIG_F2FS_FS_XATTR=y
CONFIG_F2FS_FS_POSIX_ACL=y
CONFIG_F2FS_FS_SECURITY=y
CONFIG_F2FS_CHECK_FS=y
CONFIG_F2FS_FAULT_INJECTION=y
CONFIG_F2FS_FS_COMPRESSION=y
CONFIG_F2FS_FS_LZO=y
CONFIG_F2FS_FS_LZORLE=y
CONFIG_F2FS_FS_LZ4=y
CONFIG_F2FS_FS_LZ4HC=y
CONFIG_F2FS_FS_ZSTD=y
CONFIG_F2FS_IOSTAT=y
CONFIG_F2FS_UNFAIR_RWSEM=y
CONFIG_ZONEFS_FS=y
CONFIG_FS_DAX=y
CONFIG_FS_DAX_PMD=y
CONFIG_FS_POSIX_ACL=y
CONFIG_EXPORTFS=y
CONFIG_EXPORTFS_BLOCK_OPS=y
CONFIG_FILE_LOCKING=y
CONFIG_FS_ENCRYPTION=y
CONFIG_FS_ENCRYPTION_ALGS=y
CONFIG_FS_ENCRYPTION_INLINE_CRYPT=y
CONFIG_FS_VERITY=y
CONFIG_FS_VERITY_DEBUG=y
CONFIG_FS_VERITY_BUILTIN_SIGNATURES=y
CONFIG_FSNOTIFY=y
CONFIG_DNOTIFY=y
CONFIG_INOTIFY_USER=y
CONFIG_FANOTIFY=y
CONFIG_FANOTIFY_ACCESS_PERMISSIONS=y
CONFIG_QUOTA=y
CONFIG_QUOTA_NETLINK_INTERFACE=y
CONFIG_PRINT_QUOTA_WARNING=y
CONFIG_QUOTA_DEBUG=y
CONFIG_QUOTA_TREE=y
CONFIG_QFMT_V1=y
CONFIG_QFMT_V2=y
CONFIG_QUOTACTL=y
CONFIG_AUTOFS4_FS=y
CONFIG_AUTOFS_FS=y
CONFIG_FUSE_FS=y
CONFIG_CUSE=y
CONFIG_VIRTIO_FS=y
CONFIG_FUSE_DAX=y
CONFIG_OVERLAY_FS=y
CONFIG_OVERLAY_FS_REDIRECT_DIR=y
CONFIG_OVERLAY_FS_REDIRECT_ALWAYS_FOLLOW=y
CONFIG_OVERLAY_FS_INDEX=y
CONFIG_OVERLAY_FS_XINO_AUTO=y
CONFIG_OVERLAY_FS_METACOPY=y

#
# Caches
#
CONFIG_NETFS_SUPPORT=y
CONFIG_NETFS_STATS=y
CONFIG_FSCACHE=y
CONFIG_FSCACHE_STATS=y
CONFIG_FSCACHE_DEBUG=y
CONFIG_CACHEFILES=y
CONFIG_CACHEFILES_DEBUG=y
CONFIG_CACHEFILES_ERROR_INJECTION=y
CONFIG_CACHEFILES_ONDEMAND=y
# end of Caches

#
# CD-ROM/DVD Filesystems
#
CONFIG_ISO9660_FS=y
CONFIG_JOLIET=y
CONFIG_ZISOFS=y
CONFIG_UDF_FS=y
# end of CD-ROM/DVD Filesystems

#
# DOS/FAT/EXFAT/NT Filesystems
#
CONFIG_FAT_FS=y
CONFIG_MSDOS_FS=y
CONFIG_VFAT_FS=y
CONFIG_FAT_DEFAULT_CODEPAGE=437
CONFIG_FAT_DEFAULT_IOCHARSET="iso8859-1"
CONFIG_FAT_DEFAULT_UTF8=y
CONFIG_FAT_KUNIT_TEST=y
CONFIG_EXFAT_FS=y
CONFIG_EXFAT_DEFAULT_IOCHARSET="utf8"
CONFIG_NTFS_FS=y
CONFIG_NTFS_DEBUG=y
CONFIG_NTFS_RW=y
CONFIG_NTFS3_FS=y
CONFIG_NTFS3_64BIT_CLUSTER=y
CONFIG_NTFS3_LZX_XPRESS=y
CONFIG_NTFS3_FS_POSIX_ACL=y
# end of DOS/FAT/EXFAT/NT Filesystems

#
# Pseudo filesystems
#
CONFIG_PROC_FS=y
CONFIG_PROC_KCORE=y
CONFIG_PROC_VMCORE=y
CONFIG_PROC_VMCORE_DEVICE_DUMP=y
CONFIG_PROC_SYSCTL=y
CONFIG_PROC_PAGE_MONITOR=y
CONFIG_PROC_CHILDREN=y
CONFIG_PROC_PID_ARCH_STATUS=y
CONFIG_PROC_CPU_RESCTRL=y
CONFIG_KERNFS=y
CONFIG_SYSFS=y
CONFIG_TMPFS=y
CONFIG_TMPFS_POSIX_ACL=y
CONFIG_TMPFS_XATTR=y
CONFIG_TMPFS_INODE64=y
CONFIG_HUGETLBFS=y
CONFIG_HUGETLB_PAGE=y
CONFIG_ARCH_WANT_HUGETLB_PAGE_OPTIMIZE_VMEMMAP=y
CONFIG_HUGETLB_PAGE_OPTIMIZE_VMEMMAP=y
CONFIG_HUGETLB_PAGE_OPTIMIZE_VMEMMAP_DEFAULT_ON=y
CONFIG_MEMFD_CREATE=y
CONFIG_ARCH_HAS_GIGANTIC_PAGE=y
CONFIG_CONFIGFS_FS=y
CONFIG_EFIVAR_FS=y
# end of Pseudo filesystems

CONFIG_MISC_FILESYSTEMS=y
CONFIG_ORANGEFS_FS=y
CONFIG_ADFS_FS=y
CONFIG_ADFS_FS_RW=y
CONFIG_AFFS_FS=y
CONFIG_ECRYPT_FS=y
CONFIG_ECRYPT_FS_MESSAGING=y
CONFIG_HFS_FS=y
CONFIG_HFSPLUS_FS=y
CONFIG_BEFS_FS=y
CONFIG_BEFS_DEBUG=y
CONFIG_BFS_FS=y
CONFIG_EFS_FS=y
CONFIG_JFFS2_FS=y
CONFIG_JFFS2_FS_DEBUG=0
CONFIG_JFFS2_FS_WRITEBUFFER=y
CONFIG_JFFS2_FS_WBUF_VERIFY=y
CONFIG_JFFS2_SUMMARY=y
CONFIG_JFFS2_FS_XATTR=y
CONFIG_JFFS2_FS_POSIX_ACL=y
CONFIG_JFFS2_FS_SECURITY=y
CONFIG_JFFS2_COMPRESSION_OPTIONS=y
CONFIG_JFFS2_ZLIB=y
CONFIG_JFFS2_LZO=y
CONFIG_JFFS2_RTIME=y
CONFIG_JFFS2_RUBIN=y
# CONFIG_JFFS2_CMODE_NONE is not set
CONFIG_JFFS2_CMODE_PRIORITY=y
# CONFIG_JFFS2_CMODE_SIZE is not set
# CONFIG_JFFS2_CMODE_FAVOURLZO is not set
CONFIG_UBIFS_FS=y
CONFIG_UBIFS_FS_ADVANCED_COMPR=y
CONFIG_UBIFS_FS_LZO=y
CONFIG_UBIFS_FS_ZLIB=y
CONFIG_UBIFS_FS_ZSTD=y
CONFIG_UBIFS_ATIME_SUPPORT=y
CONFIG_UBIFS_FS_XATTR=y
CONFIG_UBIFS_FS_SECURITY=y
CONFIG_UBIFS_FS_AUTHENTICATION=y
CONFIG_CRAMFS=y
CONFIG_CRAMFS_BLOCKDEV=y
CONFIG_CRAMFS_MTD=y
CONFIG_SQUASHFS=y
CONFIG_SQUASHFS_FILE_CACHE=y
# CONFIG_SQUASHFS_FILE_DIRECT is not set
CONFIG_SQUASHFS_DECOMP_SINGLE=y
# CONFIG_SQUASHFS_DECOMP_MULTI is not set
# CONFIG_SQUASHFS_DECOMP_MULTI_PERCPU is not set
CONFIG_SQUASHFS_XATTR=y
CONFIG_SQUASHFS_ZLIB=y
CONFIG_SQUASHFS_LZ4=y
CONFIG_SQUASHFS_LZO=y
CONFIG_SQUASHFS_XZ=y
CONFIG_SQUASHFS_ZSTD=y
CONFIG_SQUASHFS_4K_DEVBLK_SIZE=y
CONFIG_SQUASHFS_EMBEDDED=y
CONFIG_SQUASHFS_FRAGMENT_CACHE_SIZE=3
CONFIG_VXFS_FS=y
CONFIG_MINIX_FS=y
CONFIG_OMFS_FS=y
CONFIG_HPFS_FS=y
CONFIG_QNX4FS_FS=y
CONFIG_QNX6FS_FS=y
CONFIG_QNX6FS_DEBUG=y
CONFIG_ROMFS_FS=y
CONFIG_ROMFS_BACKED_BY_BLOCK=y
# CONFIG_ROMFS_BACKED_BY_MTD is not set
# CONFIG_ROMFS_BACKED_BY_BOTH is not set
CONFIG_ROMFS_ON_BLOCK=y
CONFIG_PSTORE=y
CONFIG_PSTORE_DEFAULT_KMSG_BYTES=10240
CONFIG_PSTORE_DEFLATE_COMPRESS=y
CONFIG_PSTORE_LZO_COMPRESS=y
CONFIG_PSTORE_LZ4_COMPRESS=y
CONFIG_PSTORE_LZ4HC_COMPRESS=y
CONFIG_PSTORE_842_COMPRESS=y
CONFIG_PSTORE_ZSTD_COMPRESS=y
CONFIG_PSTORE_COMPRESS=y
CONFIG_PSTORE_DEFLATE_COMPRESS_DEFAULT=y
# CONFIG_PSTORE_LZO_COMPRESS_DEFAULT is not set
# CONFIG_PSTORE_LZ4_COMPRESS_DEFAULT is not set
# CONFIG_PSTORE_LZ4HC_COMPRESS_DEFAULT is not set
# CONFIG_PSTORE_842_COMPRESS_DEFAULT is not set
# CONFIG_PSTORE_ZSTD_COMPRESS_DEFAULT is not set
CONFIG_PSTORE_COMPRESS_DEFAULT="deflate"
CONFIG_PSTORE_CONSOLE=y
CONFIG_PSTORE_PMSG=y
CONFIG_PSTORE_FTRACE=y
CONFIG_PSTORE_RAM=y
CONFIG_PSTORE_ZONE=y
CONFIG_PSTORE_BLK=y
CONFIG_PSTORE_BLK_BLKDEV=""
CONFIG_PSTORE_BLK_KMSG_SIZE=64
CONFIG_PSTORE_BLK_MAX_REASON=2
CONFIG_PSTORE_BLK_PMSG_SIZE=64
CONFIG_PSTORE_BLK_CONSOLE_SIZE=64
CONFIG_PSTORE_BLK_FTRACE_SIZE=64
CONFIG_SYSV_FS=y
CONFIG_UFS_FS=y
CONFIG_UFS_FS_WRITE=y
CONFIG_UFS_DEBUG=y
CONFIG_EROFS_FS=y
CONFIG_EROFS_FS_DEBUG=y
CONFIG_EROFS_FS_XATTR=y
CONFIG_EROFS_FS_POSIX_ACL=y
CONFIG_EROFS_FS_SECURITY=y
CONFIG_EROFS_FS_ZIP=y
CONFIG_EROFS_FS_ZIP_LZMA=y
CONFIG_EROFS_FS_ONDEMAND=y
CONFIG_VBOXSF_FS=y
CONFIG_NETWORK_FILESYSTEMS=y
CONFIG_NFS_FS=y
CONFIG_NFS_V2=y
CONFIG_NFS_V3=y
CONFIG_NFS_V3_ACL=y
CONFIG_NFS_V4=y
CONFIG_NFS_SWAP=y
CONFIG_NFS_V4_1=y
CONFIG_NFS_V4_2=y
CONFIG_PNFS_FILE_LAYOUT=y
CONFIG_PNFS_BLOCK=y
CONFIG_PNFS_FLEXFILE_LAYOUT=y
CONFIG_NFS_V4_1_IMPLEMENTATION_ID_DOMAIN="kernel.org"
CONFIG_NFS_V4_1_MIGRATION=y
CONFIG_NFS_V4_SECURITY_LABEL=y
CONFIG_ROOT_NFS=y
CONFIG_NFS_FSCACHE=y
CONFIG_NFS_USE_LEGACY_DNS=y
CONFIG_NFS_DEBUG=y
CONFIG_NFS_DISABLE_UDP_SUPPORT=y
CONFIG_NFS_V4_2_READ_PLUS=y
CONFIG_NFSD=y
CONFIG_NFSD_V2_ACL=y
CONFIG_NFSD_V3_ACL=y
CONFIG_NFSD_V4=y
CONFIG_NFSD_PNFS=y
CONFIG_NFSD_BLOCKLAYOUT=y
CONFIG_NFSD_SCSILAYOUT=y
CONFIG_NFSD_FLEXFILELAYOUT=y
CONFIG_NFSD_V4_2_INTER_SSC=y
CONFIG_NFSD_V4_SECURITY_LABEL=y
CONFIG_GRACE_PERIOD=y
CONFIG_LOCKD=y
CONFIG_LOCKD_V4=y
CONFIG_NFS_ACL_SUPPORT=y
CONFIG_NFS_COMMON=y
CONFIG_NFS_V4_2_SSC_HELPER=y
CONFIG_SUNRPC=y
CONFIG_SUNRPC_GSS=y
CONFIG_SUNRPC_BACKCHANNEL=y
CONFIG_SUNRPC_SWAP=y
CONFIG_RPCSEC_GSS_KRB5=y
CONFIG_SUNRPC_DISABLE_INSECURE_ENCTYPES=y
CONFIG_SUNRPC_DEBUG=y
CONFIG_SUNRPC_XPRT_RDMA=y
CONFIG_CEPH_FS=y
CONFIG_CEPH_FSCACHE=y
CONFIG_CEPH_FS_POSIX_ACL=y
CONFIG_CEPH_FS_SECURITY_LABEL=y
CONFIG_CIFS=y
CONFIG_CIFS_STATS2=y
CONFIG_CIFS_ALLOW_INSECURE_LEGACY=y
CONFIG_CIFS_UPCALL=y
CONFIG_CIFS_XATTR=y
CONFIG_CIFS_POSIX=y
CONFIG_CIFS_DEBUG=y
CONFIG_CIFS_DEBUG2=y
CONFIG_CIFS_DEBUG_DUMP_KEYS=y
CONFIG_CIFS_DFS_UPCALL=y
CONFIG_CIFS_SWN_UPCALL=y
CONFIG_CIFS_SMB_DIRECT=y
CONFIG_CIFS_FSCACHE=y
CONFIG_CIFS_ROOT=y
CONFIG_SMB_SERVER=y
CONFIG_SMB_SERVER_SMBDIRECT=y
CONFIG_SMB_SERVER_CHECK_CAP_NET_ADMIN=y
CONFIG_SMB_SERVER_KERBEROS5=y
CONFIG_SMBFS_COMMON=y
CONFIG_CODA_FS=y
CONFIG_AFS_FS=y
CONFIG_AFS_DEBUG=y
CONFIG_AFS_FSCACHE=y
CONFIG_AFS_DEBUG_CURSOR=y
CONFIG_9P_FS=y
CONFIG_9P_FSCACHE=y
CONFIG_9P_FS_POSIX_ACL=y
CONFIG_9P_FS_SECURITY=y
CONFIG_NLS=y
CONFIG_NLS_DEFAULT="iso8859-1"
CONFIG_NLS_CODEPAGE_437=y
CONFIG_NLS_CODEPAGE_737=y
CONFIG_NLS_CODEPAGE_775=y
CONFIG_NLS_CODEPAGE_850=y
CONFIG_NLS_CODEPAGE_852=y
CONFIG_NLS_CODEPAGE_855=y
CONFIG_NLS_CODEPAGE_857=y
CONFIG_NLS_CODEPAGE_860=y
CONFIG_NLS_CODEPAGE_861=y
CONFIG_NLS_CODEPAGE_862=y
CONFIG_NLS_CODEPAGE_863=y
CONFIG_NLS_CODEPAGE_864=y
CONFIG_NLS_CODEPAGE_865=y
CONFIG_NLS_CODEPAGE_866=y
CONFIG_NLS_CODEPAGE_869=y
CONFIG_NLS_CODEPAGE_936=y
CONFIG_NLS_CODEPAGE_950=y
CONFIG_NLS_CODEPAGE_932=y
CONFIG_NLS_CODEPAGE_949=y
CONFIG_NLS_CODEPAGE_874=y
CONFIG_NLS_ISO8859_8=y
CONFIG_NLS_CODEPAGE_1250=y
CONFIG_NLS_CODEPAGE_1251=y
CONFIG_NLS_ASCII=y
CONFIG_NLS_ISO8859_1=y
CONFIG_NLS_ISO8859_2=y
CONFIG_NLS_ISO8859_3=y
CONFIG_NLS_ISO8859_4=y
CONFIG_NLS_ISO8859_5=y
CONFIG_NLS_ISO8859_6=y
CONFIG_NLS_ISO8859_7=y
CONFIG_NLS_ISO8859_9=y
CONFIG_NLS_ISO8859_13=y
CONFIG_NLS_ISO8859_14=y
CONFIG_NLS_ISO8859_15=y
CONFIG_NLS_KOI8_R=y
CONFIG_NLS_KOI8_U=y
CONFIG_NLS_MAC_ROMAN=y
CONFIG_NLS_MAC_CELTIC=y
CONFIG_NLS_MAC_CENTEURO=y
CONFIG_NLS_MAC_CROATIAN=y
CONFIG_NLS_MAC_CYRILLIC=y
CONFIG_NLS_MAC_GAELIC=y
CONFIG_NLS_MAC_GREEK=y
CONFIG_NLS_MAC_ICELAND=y
CONFIG_NLS_MAC_INUIT=y
CONFIG_NLS_MAC_ROMANIAN=y
CONFIG_NLS_MAC_TURKISH=y
CONFIG_NLS_UTF8=y
CONFIG_DLM=y
CONFIG_DLM_DEPRECATED_API=y
CONFIG_DLM_DEBUG=y
CONFIG_UNICODE=y
CONFIG_UNICODE_NORMALIZATION_SELFTEST=y
CONFIG_IO_WQ=y
# end of File systems

#
# Security options
#
CONFIG_KEYS=y
CONFIG_KEYS_REQUEST_CACHE=y
CONFIG_PERSISTENT_KEYRINGS=y
CONFIG_BIG_KEYS=y
CONFIG_TRUSTED_KEYS=y
CONFIG_TRUSTED_KEYS_TPM=y
CONFIG_TRUSTED_KEYS_TEE=y
CONFIG_ENCRYPTED_KEYS=y
CONFIG_USER_DECRYPTED_DATA=y
CONFIG_KEY_DH_OPERATIONS=y
CONFIG_KEY_NOTIFICATIONS=y
CONFIG_SECURITY_DMESG_RESTRICT=y
CONFIG_SECURITY=y
CONFIG_SECURITY_WRITABLE_HOOKS=y
CONFIG_SECURITYFS=y
CONFIG_SECURITY_NETWORK=y
CONFIG_SECURITY_INFINIBAND=y
CONFIG_SECURITY_NETWORK_XFRM=y
CONFIG_SECURITY_PATH=y
CONFIG_INTEL_TXT=y
CONFIG_LSM_MMAP_MIN_ADDR=65536
CONFIG_HAVE_HARDENED_USERCOPY_ALLOCATOR=y
CONFIG_HARDENED_USERCOPY=y
CONFIG_FORTIFY_SOURCE=y
CONFIG_STATIC_USERMODEHELPER=y
CONFIG_STATIC_USERMODEHELPER_PATH="/sbin/usermode-helper"
CONFIG_SECURITY_SELINUX=y
CONFIG_SECURITY_SELINUX_BOOTPARAM=y
CONFIG_SECURITY_SELINUX_DISABLE=y
CONFIG_SECURITY_SELINUX_DEVELOP=y
CONFIG_SECURITY_SELINUX_AVC_STATS=y
CONFIG_SECURITY_SELINUX_CHECKREQPROT_VALUE=0
CONFIG_SECURITY_SELINUX_SIDTAB_HASH_BITS=9
CONFIG_SECURITY_SELINUX_SID2STR_CACHE_SIZE=256
CONFIG_SECURITY_SMACK=y
CONFIG_SECURITY_SMACK_BRINGUP=y
CONFIG_SECURITY_SMACK_NETFILTER=y
CONFIG_SECURITY_SMACK_APPEND_SIGNALS=y
CONFIG_SECURITY_TOMOYO=y
CONFIG_SECURITY_TOMOYO_MAX_ACCEPT_ENTRY=2048
CONFIG_SECURITY_TOMOYO_MAX_AUDIT_LOG=1024
CONFIG_SECURITY_TOMOYO_OMIT_USERSPACE_LOADER=y
CONFIG_SECURITY_TOMOYO_INSECURE_BUILTIN_SETTING=y
CONFIG_SECURITY_APPARMOR=y
CONFIG_SECURITY_APPARMOR_DEBUG=y
CONFIG_SECURITY_APPARMOR_DEBUG_ASSERTS=y
CONFIG_SECURITY_APPARMOR_DEBUG_MESSAGES=y
CONFIG_SECURITY_APPARMOR_INTROSPECT_POLICY=y
CONFIG_SECURITY_APPARMOR_HASH=y
CONFIG_SECURITY_APPARMOR_HASH_DEFAULT=y
CONFIG_SECURITY_APPARMOR_EXPORT_BINARY=y
CONFIG_SECURITY_APPARMOR_PARANOID_LOAD=y
CONFIG_SECURITY_APPARMOR_KUNIT_TEST=y
CONFIG_SECURITY_LOADPIN=y
CONFIG_SECURITY_LOADPIN_ENFORCE=y
CONFIG_SECURITY_LOADPIN_VERITY=y
CONFIG_SECURITY_YAMA=y
CONFIG_SECURITY_SAFESETID=y
CONFIG_SECURITY_LOCKDOWN_LSM=y
CONFIG_SECURITY_LOCKDOWN_LSM_EARLY=y
CONFIG_LOCK_DOWN_KERNEL_FORCE_NONE=y
# CONFIG_LOCK_DOWN_KERNEL_FORCE_INTEGRITY is not set
# CONFIG_LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY is not set
CONFIG_SECURITY_LANDLOCK=y
CONFIG_INTEGRITY=y
CONFIG_INTEGRITY_SIGNATURE=y
CONFIG_INTEGRITY_ASYMMETRIC_KEYS=y
CONFIG_INTEGRITY_TRUSTED_KEYRING=y
CONFIG_INTEGRITY_PLATFORM_KEYRING=y
CONFIG_LOAD_UEFI_KEYS=y
CONFIG_INTEGRITY_AUDIT=y
CONFIG_IMA=y
CONFIG_IMA_KEXEC=y
CONFIG_IMA_MEASURE_PCR_IDX=10
CONFIG_IMA_LSM_RULES=y
CONFIG_IMA_NG_TEMPLATE=y
# CONFIG_IMA_SIG_TEMPLATE is not set
CONFIG_IMA_DEFAULT_TEMPLATE="ima-ng"
CONFIG_IMA_DEFAULT_HASH_SHA1=y
# CONFIG_IMA_DEFAULT_HASH_SHA256 is not set
# CONFIG_IMA_DEFAULT_HASH_SHA512 is not set
# CONFIG_IMA_DEFAULT_HASH_WP512 is not set
# CONFIG_IMA_DEFAULT_HASH_SM3 is not set
CONFIG_IMA_DEFAULT_HASH="sha1"
CONFIG_IMA_WRITE_POLICY=y
CONFIG_IMA_READ_POLICY=y
CONFIG_IMA_APPRAISE=y
CONFIG_IMA_ARCH_POLICY=y
CONFIG_IMA_APPRAISE_BUILD_POLICY=y
CONFIG_IMA_APPRAISE_REQUIRE_FIRMWARE_SIGS=y
CONFIG_IMA_APPRAISE_REQUIRE_KEXEC_SIGS=y
CONFIG_IMA_APPRAISE_REQUIRE_MODULE_SIGS=y
CONFIG_IMA_APPRAISE_REQUIRE_POLICY_SIGS=y
CONFIG_IMA_APPRAISE_BOOTPARAM=y
CONFIG_IMA_APPRAISE_MODSIG=y
CONFIG_IMA_TRUSTED_KEYRING=y
CONFIG_IMA_KEYRINGS_PERMIT_SIGNED_BY_BUILTIN_OR_SECONDARY=y
CONFIG_IMA_BLACKLIST_KEYRING=y
CONFIG_IMA_LOAD_X509=y
CONFIG_IMA_X509_PATH="/etc/keys/x509_ima.der"
CONFIG_IMA_APPRAISE_SIGNED_INIT=y
CONFIG_IMA_MEASURE_ASYMMETRIC_KEYS=y
CONFIG_IMA_QUEUE_EARLY_BOOT_KEYS=y
CONFIG_IMA_SECURE_AND_OR_TRUSTED_BOOT=y
CONFIG_IMA_DISABLE_HTABLE=y
CONFIG_EVM=y
CONFIG_EVM_ATTR_FSUUID=y
CONFIG_EVM_EXTRA_SMACK_XATTRS=y
CONFIG_EVM_ADD_XATTRS=y
CONFIG_EVM_LOAD_X509=y
CONFIG_EVM_X509_PATH="/etc/keys/x509_evm.der"
CONFIG_DEFAULT_SECURITY_SELINUX=y
# CONFIG_DEFAULT_SECURITY_SMACK is not set
# CONFIG_DEFAULT_SECURITY_TOMOYO is not set
# CONFIG_DEFAULT_SECURITY_APPARMOR is not set
# CONFIG_DEFAULT_SECURITY_DAC is not set
CONFIG_LSM="landlock,lockdown,yama,loadpin,safesetid,integrity,selinux,smack,tomoyo,apparmor,bpf"

#
# Kernel hardening options
#

#
# Memory initialization
#
CONFIG_INIT_STACK_NONE=y
# CONFIG_GCC_PLUGIN_STRUCTLEAK_USER is not set
CONFIG_GCC_PLUGIN_STACKLEAK=y
# CONFIG_GCC_PLUGIN_STACKLEAK_VERBOSE is not set
CONFIG_STACKLEAK_TRACK_MIN_SIZE=100
CONFIG_STACKLEAK_METRICS=y
CONFIG_STACKLEAK_RUNTIME_DISABLE=y
CONFIG_INIT_ON_ALLOC_DEFAULT_ON=y
CONFIG_INIT_ON_FREE_DEFAULT_ON=y
CONFIG_CC_HAS_ZERO_CALL_USED_REGS=y
CONFIG_ZERO_CALL_USED_REGS=y
# end of Memory initialization

# CONFIG_RANDSTRUCT_NONE is not set
CONFIG_RANDSTRUCT_FULL=y
# CONFIG_RANDSTRUCT_PERFORMANCE is not set
CONFIG_RANDSTRUCT=y
CONFIG_GCC_PLUGIN_RANDSTRUCT=y
# end of Kernel hardening options
# end of Security options

CONFIG_XOR_BLOCKS=y
CONFIG_ASYNC_CORE=y
CONFIG_ASYNC_MEMCPY=y
CONFIG_ASYNC_XOR=y
CONFIG_ASYNC_PQ=y
CONFIG_ASYNC_RAID6_RECOV=y
CONFIG_CRYPTO=y

#
# Crypto core or helper
#
CONFIG_CRYPTO_ALGAPI=y
CONFIG_CRYPTO_ALGAPI2=y
CONFIG_CRYPTO_AEAD=y
CONFIG_CRYPTO_AEAD2=y
CONFIG_CRYPTO_SKCIPHER=y
CONFIG_CRYPTO_SKCIPHER2=y
CONFIG_CRYPTO_HASH=y
CONFIG_CRYPTO_HASH2=y
CONFIG_CRYPTO_RNG=y
CONFIG_CRYPTO_RNG2=y
CONFIG_CRYPTO_RNG_DEFAULT=y
CONFIG_CRYPTO_AKCIPHER2=y
CONFIG_CRYPTO_AKCIPHER=y
CONFIG_CRYPTO_KPP2=y
CONFIG_CRYPTO_KPP=y
CONFIG_CRYPTO_ACOMP2=y
CONFIG_CRYPTO_MANAGER=y
CONFIG_CRYPTO_MANAGER2=y
CONFIG_CRYPTO_USER=y
CONFIG_CRYPTO_MANAGER_DISABLE_TESTS=y
CONFIG_CRYPTO_GF128MUL=y
CONFIG_CRYPTO_NULL=y
CONFIG_CRYPTO_NULL2=y
CONFIG_CRYPTO_PCRYPT=y
CONFIG_CRYPTO_CRYPTD=y
CONFIG_CRYPTO_AUTHENC=y
CONFIG_CRYPTO_TEST=y
CONFIG_CRYPTO_SIMD=y
CONFIG_CRYPTO_ENGINE=y

#
# Public-key cryptography
#
CONFIG_CRYPTO_RSA=y
CONFIG_CRYPTO_DH=y
CONFIG_CRYPTO_DH_RFC7919_GROUPS=y
CONFIG_CRYPTO_ECC=y
CONFIG_CRYPTO_ECDH=y
CONFIG_CRYPTO_ECDSA=y
CONFIG_CRYPTO_ECRDSA=y
CONFIG_CRYPTO_SM2=y
CONFIG_CRYPTO_CURVE25519=y
CONFIG_CRYPTO_CURVE25519_X86=y

#
# Authenticated Encryption with Associated Data
#
CONFIG_CRYPTO_CCM=y
CONFIG_CRYPTO_GCM=y
CONFIG_CRYPTO_CHACHA20POLY1305=y
CONFIG_CRYPTO_AEGIS128=y
CONFIG_CRYPTO_AEGIS128_AESNI_SSE2=y
CONFIG_CRYPTO_SEQIV=y
CONFIG_CRYPTO_ECHAINIV=y

#
# Block modes
#
CONFIG_CRYPTO_CBC=y
CONFIG_CRYPTO_CFB=y
CONFIG_CRYPTO_CTR=y
CONFIG_CRYPTO_CTS=y
CONFIG_CRYPTO_ECB=y
CONFIG_CRYPTO_LRW=y
CONFIG_CRYPTO_OFB=y
CONFIG_CRYPTO_PCBC=y
CONFIG_CRYPTO_XCTR=y
CONFIG_CRYPTO_XTS=y
CONFIG_CRYPTO_KEYWRAP=y
CONFIG_CRYPTO_NHPOLY1305=y
CONFIG_CRYPTO_NHPOLY1305_SSE2=y
CONFIG_CRYPTO_NHPOLY1305_AVX2=y
CONFIG_CRYPTO_ADIANTUM=y
CONFIG_CRYPTO_HCTR2=y
CONFIG_CRYPTO_ESSIV=y

#
# Hash modes
#
CONFIG_CRYPTO_CMAC=y
CONFIG_CRYPTO_HMAC=y
CONFIG_CRYPTO_XCBC=y
CONFIG_CRYPTO_VMAC=y

#
# Digest
#
CONFIG_CRYPTO_CRC32C=y
CONFIG_CRYPTO_CRC32C_INTEL=y
CONFIG_CRYPTO_CRC32=y
CONFIG_CRYPTO_CRC32_PCLMUL=y
CONFIG_CRYPTO_XXHASH=y
CONFIG_CRYPTO_BLAKE2B=y
CONFIG_CRYPTO_BLAKE2S_X86=y
CONFIG_CRYPTO_CRCT10DIF=y
CONFIG_CRYPTO_CRCT10DIF_PCLMUL=y
CONFIG_CRYPTO_CRC64_ROCKSOFT=y
CONFIG_CRYPTO_GHASH=y
CONFIG_CRYPTO_POLYVAL=y
CONFIG_CRYPTO_POLYVAL_CLMUL_NI=y
CONFIG_CRYPTO_POLY1305=y
CONFIG_CRYPTO_POLY1305_X86_64=y
CONFIG_CRYPTO_MD4=y
CONFIG_CRYPTO_MD5=y
CONFIG_CRYPTO_MICHAEL_MIC=y
CONFIG_CRYPTO_RMD160=y
CONFIG_CRYPTO_SHA1=y
CONFIG_CRYPTO_SHA1_SSSE3=y
CONFIG_CRYPTO_SHA256_SSSE3=y
CONFIG_CRYPTO_SHA512_SSSE3=y
CONFIG_CRYPTO_SHA256=y
CONFIG_CRYPTO_SHA512=y
CONFIG_CRYPTO_SHA3=y
CONFIG_CRYPTO_SM3=y
CONFIG_CRYPTO_SM3_GENERIC=y
CONFIG_CRYPTO_SM3_AVX_X86_64=y
CONFIG_CRYPTO_STREEBOG=y
CONFIG_CRYPTO_WP512=y
CONFIG_CRYPTO_GHASH_CLMUL_NI_INTEL=y

#
# Ciphers
#
CONFIG_CRYPTO_AES=y
CONFIG_CRYPTO_AES_TI=y
CONFIG_CRYPTO_AES_NI_INTEL=y
CONFIG_CRYPTO_ANUBIS=y
CONFIG_CRYPTO_ARC4=y
CONFIG_CRYPTO_BLOWFISH=y
CONFIG_CRYPTO_BLOWFISH_COMMON=y
CONFIG_CRYPTO_BLOWFISH_X86_64=y
CONFIG_CRYPTO_CAMELLIA=y
CONFIG_CRYPTO_CAMELLIA_X86_64=y
CONFIG_CRYPTO_CAMELLIA_AESNI_AVX_X86_64=y
CONFIG_CRYPTO_CAMELLIA_AESNI_AVX2_X86_64=y
CONFIG_CRYPTO_CAST_COMMON=y
CONFIG_CRYPTO_CAST5=y
CONFIG_CRYPTO_CAST5_AVX_X86_64=y
CONFIG_CRYPTO_CAST6=y
CONFIG_CRYPTO_CAST6_AVX_X86_64=y
CONFIG_CRYPTO_DES=y
CONFIG_CRYPTO_DES3_EDE_X86_64=y
CONFIG_CRYPTO_FCRYPT=y
CONFIG_CRYPTO_KHAZAD=y
CONFIG_CRYPTO_CHACHA20=y
CONFIG_CRYPTO_CHACHA20_X86_64=y
CONFIG_CRYPTO_SEED=y
CONFIG_CRYPTO_ARIA=y
CONFIG_CRYPTO_SERPENT=y
CONFIG_CRYPTO_SERPENT_SSE2_X86_64=y
CONFIG_CRYPTO_SERPENT_AVX_X86_64=y
CONFIG_CRYPTO_SERPENT_AVX2_X86_64=y
CONFIG_CRYPTO_SM4=y
CONFIG_CRYPTO_SM4_GENERIC=y
CONFIG_CRYPTO_SM4_AESNI_AVX_X86_64=y
CONFIG_CRYPTO_SM4_AESNI_AVX2_X86_64=y
CONFIG_CRYPTO_TEA=y
CONFIG_CRYPTO_TWOFISH=y
CONFIG_CRYPTO_TWOFISH_COMMON=y
CONFIG_CRYPTO_TWOFISH_X86_64=y
CONFIG_CRYPTO_TWOFISH_X86_64_3WAY=y
CONFIG_CRYPTO_TWOFISH_AVX_X86_64=y

#
# Compression
#
CONFIG_CRYPTO_DEFLATE=y
CONFIG_CRYPTO_LZO=y
CONFIG_CRYPTO_842=y
CONFIG_CRYPTO_LZ4=y
CONFIG_CRYPTO_LZ4HC=y
CONFIG_CRYPTO_ZSTD=y

#
# Random Number Generation
#
CONFIG_CRYPTO_ANSI_CPRNG=y
CONFIG_CRYPTO_DRBG_MENU=y
CONFIG_CRYPTO_DRBG_HMAC=y
CONFIG_CRYPTO_DRBG_HASH=y
CONFIG_CRYPTO_DRBG_CTR=y
CONFIG_CRYPTO_DRBG=y
CONFIG_CRYPTO_JITTERENTROPY=y
CONFIG_CRYPTO_KDF800108_CTR=y
CONFIG_CRYPTO_USER_API=y
CONFIG_CRYPTO_USER_API_HASH=y
CONFIG_CRYPTO_USER_API_SKCIPHER=y
CONFIG_CRYPTO_USER_API_RNG=y
CONFIG_CRYPTO_USER_API_RNG_CAVP=y
CONFIG_CRYPTO_USER_API_AEAD=y
CONFIG_CRYPTO_USER_API_ENABLE_OBSOLETE=y
CONFIG_CRYPTO_STATS=y
CONFIG_CRYPTO_HASH_INFO=y
CONFIG_CRYPTO_HW=y
CONFIG_CRYPTO_DEV_PADLOCK=y
CONFIG_CRYPTO_DEV_PADLOCK_AES=y
CONFIG_CRYPTO_DEV_PADLOCK_SHA=y
CONFIG_CRYPTO_DEV_ATMEL_I2C=y
CONFIG_CRYPTO_DEV_ATMEL_ECC=y
CONFIG_CRYPTO_DEV_ATMEL_SHA204A=y
CONFIG_CRYPTO_DEV_CCP=y
CONFIG_CRYPTO_DEV_CCP_DD=y
CONFIG_CRYPTO_DEV_SP_CCP=y
CONFIG_CRYPTO_DEV_CCP_CRYPTO=y
CONFIG_CRYPTO_DEV_SP_PSP=y
CONFIG_CRYPTO_DEV_CCP_DEBUGFS=y
CONFIG_CRYPTO_DEV_QAT=y
CONFIG_CRYPTO_DEV_QAT_DH895xCC=y
CONFIG_CRYPTO_DEV_QAT_C3XXX=y
CONFIG_CRYPTO_DEV_QAT_C62X=y
CONFIG_CRYPTO_DEV_QAT_4XXX=y
CONFIG_CRYPTO_DEV_QAT_DH895xCCVF=y
CONFIG_CRYPTO_DEV_QAT_C3XXXVF=y
CONFIG_CRYPTO_DEV_QAT_C62XVF=y
CONFIG_CRYPTO_DEV_NITROX=y
CONFIG_CRYPTO_DEV_NITROX_CNN55XX=y
CONFIG_CRYPTO_DEV_CHELSIO=y
CONFIG_CRYPTO_DEV_VIRTIO=y
CONFIG_CRYPTO_DEV_SAFEXCEL=y
CONFIG_CRYPTO_DEV_CCREE=y
CONFIG_CRYPTO_DEV_AMLOGIC_GXL=y
CONFIG_CRYPTO_DEV_AMLOGIC_GXL_DEBUG=y
CONFIG_ASYMMETRIC_KEY_TYPE=y
CONFIG_ASYMMETRIC_PUBLIC_KEY_SUBTYPE=y
CONFIG_X509_CERTIFICATE_PARSER=y
CONFIG_PKCS8_PRIVATE_KEY_PARSER=y
CONFIG_PKCS7_MESSAGE_PARSER=y
CONFIG_PKCS7_TEST_KEY=y
CONFIG_SIGNED_PE_FILE_VERIFICATION=y
CONFIG_FIPS_SIGNATURE_SELFTEST=y

#
# Certificates for signature checking
#
CONFIG_MODULE_SIG_KEY="certs/signing_key.pem"
CONFIG_MODULE_SIG_KEY_TYPE_RSA=y
# CONFIG_MODULE_SIG_KEY_TYPE_ECDSA is not set
CONFIG_SYSTEM_TRUSTED_KEYRING=y
CONFIG_SYSTEM_TRUSTED_KEYS=""
CONFIG_SYSTEM_EXTRA_CERTIFICATE=y
CONFIG_SYSTEM_EXTRA_CERTIFICATE_SIZE=4096
CONFIG_SECONDARY_TRUSTED_KEYRING=y
CONFIG_SYSTEM_BLACKLIST_KEYRING=y
CONFIG_SYSTEM_BLACKLIST_HASH_LIST=""
CONFIG_SYSTEM_REVOCATION_LIST=y
CONFIG_SYSTEM_REVOCATION_KEYS=""
CONFIG_SYSTEM_BLACKLIST_AUTH_UPDATE=y
# end of Certificates for signature checking

CONFIG_BINARY_PRINTF=y

#
# Library routines
#
CONFIG_RAID6_PQ=y
CONFIG_RAID6_PQ_BENCHMARK=y
CONFIG_LINEAR_RANGES=y
CONFIG_PACKING=y
CONFIG_BITREVERSE=y
CONFIG_GENERIC_STRNCPY_FROM_USER=y
CONFIG_GENERIC_STRNLEN_USER=y
CONFIG_GENERIC_NET_UTILS=y
CONFIG_CORDIC=y
CONFIG_PRIME_NUMBERS=y
CONFIG_RATIONAL=y
CONFIG_GENERIC_PCI_IOMAP=y
CONFIG_GENERIC_IOMAP=y
CONFIG_ARCH_USE_CMPXCHG_LOCKREF=y
CONFIG_ARCH_HAS_FAST_MULTIPLIER=y
CONFIG_ARCH_USE_SYM_ANNOTATIONS=y

#
# Crypto library routines
#
CONFIG_CRYPTO_LIB_AES=y
CONFIG_CRYPTO_LIB_ARC4=y
CONFIG_CRYPTO_ARCH_HAVE_LIB_BLAKE2S=y
CONFIG_CRYPTO_LIB_BLAKE2S_GENERIC=y
CONFIG_CRYPTO_ARCH_HAVE_LIB_CHACHA=y
CONFIG_CRYPTO_LIB_CHACHA_GENERIC=y
CONFIG_CRYPTO_LIB_CHACHA=y
CONFIG_CRYPTO_ARCH_HAVE_LIB_CURVE25519=y
CONFIG_CRYPTO_LIB_CURVE25519_GENERIC=y
CONFIG_CRYPTO_LIB_CURVE25519=y
CONFIG_CRYPTO_LIB_DES=y
CONFIG_CRYPTO_LIB_POLY1305_RSIZE=11
CONFIG_CRYPTO_ARCH_HAVE_LIB_POLY1305=y
CONFIG_CRYPTO_LIB_POLY1305_GENERIC=y
CONFIG_CRYPTO_LIB_POLY1305=y
CONFIG_CRYPTO_LIB_CHACHA20POLY1305=y
CONFIG_CRYPTO_LIB_SHA1=y
CONFIG_CRYPTO_LIB_SHA256=y
# end of Crypto library routines

CONFIG_LIB_MEMNEQ=y
CONFIG_CRC_CCITT=y
CONFIG_CRC16=y
CONFIG_CRC_T10DIF=y
CONFIG_CRC64_ROCKSOFT=y
CONFIG_CRC_ITU_T=y
CONFIG_CRC32=y
CONFIG_CRC32_SELFTEST=y
CONFIG_CRC32_SLICEBY8=y
# CONFIG_CRC32_SLICEBY4 is not set
# CONFIG_CRC32_SARWATE is not set
# CONFIG_CRC32_BIT is not set
CONFIG_CRC64=y
CONFIG_CRC4=y
CONFIG_CRC7=y
CONFIG_LIBCRC32C=y
CONFIG_CRC8=y
CONFIG_XXHASH=y
CONFIG_RANDOM32_SELFTEST=y
CONFIG_842_COMPRESS=y
CONFIG_842_DECOMPRESS=y
CONFIG_ZLIB_INFLATE=y
CONFIG_ZLIB_DEFLATE=y
CONFIG_LZO_COMPRESS=y
CONFIG_LZO_DECOMPRESS=y
CONFIG_LZ4_COMPRESS=y
CONFIG_LZ4HC_COMPRESS=y
CONFIG_LZ4_DECOMPRESS=y
CONFIG_ZSTD_COMPRESS=y
CONFIG_ZSTD_DECOMPRESS=y
CONFIG_XZ_DEC=y
CONFIG_XZ_DEC_X86=y
CONFIG_XZ_DEC_POWERPC=y
CONFIG_XZ_DEC_IA64=y
CONFIG_XZ_DEC_ARM=y
CONFIG_XZ_DEC_ARMTHUMB=y
CONFIG_XZ_DEC_SPARC=y
CONFIG_XZ_DEC_MICROLZMA=y
CONFIG_XZ_DEC_BCJ=y
CONFIG_XZ_DEC_TEST=y
CONFIG_DECOMPRESS_GZIP=y
CONFIG_DECOMPRESS_BZIP2=y
CONFIG_DECOMPRESS_LZMA=y
CONFIG_DECOMPRESS_XZ=y
CONFIG_DECOMPRESS_LZO=y
CONFIG_DECOMPRESS_LZ4=y
CONFIG_DECOMPRESS_ZSTD=y
CONFIG_GENERIC_ALLOCATOR=y
CONFIG_REED_SOLOMON=y
CONFIG_REED_SOLOMON_ENC8=y
CONFIG_REED_SOLOMON_DEC8=y
CONFIG_REED_SOLOMON_ENC16=y
CONFIG_REED_SOLOMON_DEC16=y
CONFIG_BCH=y
CONFIG_TEXTSEARCH=y
CONFIG_TEXTSEARCH_KMP=y
CONFIG_TEXTSEARCH_BM=y
CONFIG_TEXTSEARCH_FSM=y
CONFIG_BTREE=y
CONFIG_INTERVAL_TREE=y
CONFIG_XARRAY_MULTI=y
CONFIG_ASSOCIATIVE_ARRAY=y
CONFIG_HAS_IOMEM=y
CONFIG_HAS_IOPORT_MAP=y
CONFIG_HAS_DMA=y
CONFIG_DMA_OPS=y
CONFIG_NEED_SG_DMA_LENGTH=y
CONFIG_NEED_DMA_MAP_STATE=y
CONFIG_ARCH_DMA_ADDR_T_64BIT=y
CONFIG_DMA_DECLARE_COHERENT=y
CONFIG_ARCH_HAS_FORCE_DMA_UNENCRYPTED=y
CONFIG_SWIOTLB=y
CONFIG_DMA_RESTRICTED_POOL=y
CONFIG_DMA_COHERENT_POOL=y
CONFIG_DMA_CMA=y
CONFIG_DMA_PERNUMA_CMA=y

#
# Default contiguous memory area size:
#
CONFIG_CMA_SIZE_MBYTES=0
CONFIG_CMA_SIZE_SEL_MBYTES=y
# CONFIG_CMA_SIZE_SEL_PERCENTAGE is not set
# CONFIG_CMA_SIZE_SEL_MIN is not set
# CONFIG_CMA_SIZE_SEL_MAX is not set
CONFIG_CMA_ALIGNMENT=8
CONFIG_DMA_API_DEBUG=y
CONFIG_DMA_API_DEBUG_SG=y
CONFIG_DMA_MAP_BENCHMARK=y
CONFIG_SGL_ALLOC=y
CONFIG_IOMMU_HELPER=y
CONFIG_CHECK_SIGNATURE=y
CONFIG_CPUMASK_OFFSTACK=y
CONFIG_CPU_RMAP=y
CONFIG_DQL=y
CONFIG_GLOB=y
CONFIG_GLOB_SELFTEST=y
CONFIG_NLATTR=y
CONFIG_LRU_CACHE=y
CONFIG_CLZ_TAB=y
CONFIG_IRQ_POLL=y
CONFIG_MPILIB=y
CONFIG_SIGNATURE=y
CONFIG_DIMLIB=y
CONFIG_LIBFDT=y
CONFIG_OID_REGISTRY=y
CONFIG_UCS2_STRING=y
CONFIG_HAVE_GENERIC_VDSO=y
CONFIG_GENERIC_GETTIMEOFDAY=y
CONFIG_GENERIC_VDSO_TIME_NS=y
CONFIG_FONT_SUPPORT=y
CONFIG_FONTS=y
CONFIG_FONT_8x8=y
CONFIG_FONT_8x16=y
CONFIG_FONT_6x11=y
CONFIG_FONT_7x14=y
CONFIG_FONT_PEARL_8x8=y
CONFIG_FONT_ACORN_8x8=y
CONFIG_FONT_MINI_4x6=y
CONFIG_FONT_6x10=y
CONFIG_FONT_10x18=y
CONFIG_FONT_SUN8x16=y
CONFIG_FONT_SUN12x22=y
CONFIG_FONT_TER16x32=y
CONFIG_FONT_6x8=y
CONFIG_SG_POOL=y
CONFIG_ARCH_HAS_PMEM_API=y
CONFIG_MEMREGION=y
CONFIG_ARCH_HAS_UACCESS_FLUSHCACHE=y
CONFIG_ARCH_HAS_COPY_MC=y
CONFIG_ARCH_STACKWALK=y
CONFIG_STACKDEPOT=y
CONFIG_STACKDEPOT_ALWAYS_INIT=y
CONFIG_REF_TRACKER=y
CONFIG_SBITMAP=y
CONFIG_PARMAN=y
CONFIG_OBJAGG=y
# end of Library routines

CONFIG_PLDMFW=y
CONFIG_ASN1_ENCODER=y
CONFIG_POLYNOMIAL=y

#
# Kernel hacking
#

#
# printk and dmesg options
#
CONFIG_PRINTK_TIME=y
CONFIG_PRINTK_CALLER=y
CONFIG_STACKTRACE_BUILD_ID=y
CONFIG_CONSOLE_LOGLEVEL_DEFAULT=7
CONFIG_CONSOLE_LOGLEVEL_QUIET=4
CONFIG_MESSAGE_LOGLEVEL_DEFAULT=4
CONFIG_BOOT_PRINTK_DELAY=y
CONFIG_DYNAMIC_DEBUG=y
CONFIG_DYNAMIC_DEBUG_CORE=y
CONFIG_SYMBOLIC_ERRNAME=y
CONFIG_DEBUG_BUGVERBOSE=y
# end of printk and dmesg options

CONFIG_DEBUG_KERNEL=y
CONFIG_DEBUG_MISC=y

#
# Compile-time checks and compiler options
#
CONFIG_DEBUG_INFO_NONE=y
# CONFIG_DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT is not set
# CONFIG_DEBUG_INFO_DWARF4 is not set
# CONFIG_DEBUG_INFO_DWARF5 is not set
CONFIG_FRAME_WARN=8192
CONFIG_STRIP_ASM_SYMS=y
CONFIG_READABLE_ASM=y
CONFIG_HEADERS_INSTALL=y
CONFIG_DEBUG_SECTION_MISMATCH=y
CONFIG_SECTION_MISMATCH_WARN_ONLY=y
CONFIG_DEBUG_FORCE_FUNCTION_ALIGN_64B=y
CONFIG_OBJTOOL=y
CONFIG_NOINSTR_VALIDATION=y
CONFIG_VMLINUX_MAP=y
CONFIG_DEBUG_FORCE_WEAK_PER_CPU=y
# end of Compile-time checks and compiler options

#
# Generic Kernel Debugging Instruments
#
CONFIG_MAGIC_SYSRQ=y
CONFIG_MAGIC_SYSRQ_DEFAULT_ENABLE=0x1
CONFIG_MAGIC_SYSRQ_SERIAL=y
CONFIG_MAGIC_SYSRQ_SERIAL_SEQUENCE=""
CONFIG_DEBUG_FS=y
CONFIG_DEBUG_FS_ALLOW_ALL=y
# CONFIG_DEBUG_FS_DISALLOW_MOUNT is not set
# CONFIG_DEBUG_FS_ALLOW_NONE is not set
CONFIG_HAVE_ARCH_KGDB=y
CONFIG_KGDB=y
CONFIG_KGDB_HONOUR_BLOCKLIST=y
CONFIG_KGDB_SERIAL_CONSOLE=y
CONFIG_KGDB_TESTS=y
CONFIG_KGDB_TESTS_ON_BOOT=y
CONFIG_KGDB_TESTS_BOOT_STRING="V1F100"
CONFIG_KGDB_LOW_LEVEL_TRAP=y
CONFIG_KGDB_KDB=y
CONFIG_KDB_DEFAULT_ENABLE=0x1
CONFIG_KDB_KEYBOARD=y
CONFIG_KDB_CONTINUE_CATASTROPHIC=0
CONFIG_ARCH_HAS_EARLY_DEBUG=y
CONFIG_ARCH_HAS_UBSAN_SANITIZE_ALL=y
CONFIG_UBSAN=y
# CONFIG_UBSAN_TRAP is not set
CONFIG_CC_HAS_UBSAN_BOUNDS=y
CONFIG_UBSAN_BOUNDS=y
CONFIG_UBSAN_ONLY_BOUNDS=y
CONFIG_UBSAN_SHIFT=y
CONFIG_UBSAN_DIV_ZERO=y
CONFIG_UBSAN_BOOL=y
CONFIG_UBSAN_ENUM=y
# CONFIG_UBSAN_ALIGNMENT is not set
CONFIG_UBSAN_SANITIZE_ALL=y
CONFIG_TEST_UBSAN=m
CONFIG_HAVE_ARCH_KCSAN=y
CONFIG_HAVE_KCSAN_COMPILER=y
# end of Generic Kernel Debugging Instruments

#
# Networking Debugging
#
CONFIG_NET_DEV_REFCNT_TRACKER=y
CONFIG_NET_NS_REFCNT_TRACKER=y
CONFIG_DEBUG_NET=y
# end of Networking Debugging

#
# Memory Debugging
#
CONFIG_PAGE_EXTENSION=y
CONFIG_DEBUG_PAGEALLOC=y
CONFIG_DEBUG_PAGEALLOC_ENABLE_DEFAULT=y
CONFIG_SLUB_DEBUG=y
CONFIG_SLUB_DEBUG_ON=y
CONFIG_PAGE_OWNER=y
CONFIG_PAGE_TABLE_CHECK=y
CONFIG_PAGE_TABLE_CHECK_ENFORCED=y
CONFIG_PAGE_POISONING=y
CONFIG_DEBUG_PAGE_REF=y
CONFIG_DEBUG_RODATA_TEST=y
CONFIG_ARCH_HAS_DEBUG_WX=y
CONFIG_DEBUG_WX=y
CONFIG_GENERIC_PTDUMP=y
CONFIG_PTDUMP_CORE=y
CONFIG_PTDUMP_DEBUGFS=y
CONFIG_DEBUG_OBJECTS=y
CONFIG_DEBUG_OBJECTS_SELFTEST=y
CONFIG_DEBUG_OBJECTS_FREE=y
CONFIG_DEBUG_OBJECTS_TIMERS=y
CONFIG_DEBUG_OBJECTS_WORK=y
CONFIG_DEBUG_OBJECTS_RCU_HEAD=y
CONFIG_DEBUG_OBJECTS_PERCPU_COUNTER=y
CONFIG_DEBUG_OBJECTS_ENABLE_DEFAULT=1
CONFIG_SHRINKER_DEBUG=y
CONFIG_HAVE_DEBUG_KMEMLEAK=y
CONFIG_DEBUG_KMEMLEAK=y
CONFIG_DEBUG_KMEMLEAK_MEM_POOL_SIZE=16000
CONFIG_DEBUG_KMEMLEAK_TEST=m
CONFIG_DEBUG_KMEMLEAK_DEFAULT_OFF=y
CONFIG_DEBUG_KMEMLEAK_AUTO_SCAN=y
CONFIG_DEBUG_STACK_USAGE=y
CONFIG_SCHED_STACK_END_CHECK=y
CONFIG_ARCH_HAS_DEBUG_VM_PGTABLE=y
CONFIG_DEBUG_VM=y
CONFIG_DEBUG_VM_MAPLE_TREE=y
CONFIG_DEBUG_VM_RB=y
CONFIG_DEBUG_VM_PGFLAGS=y
CONFIG_DEBUG_VM_PGTABLE=y
CONFIG_ARCH_HAS_DEBUG_VIRTUAL=y
CONFIG_DEBUG_VIRTUAL=y
CONFIG_DEBUG_MEMORY_INIT=y
CONFIG_MEMORY_NOTIFIER_ERROR_INJECT=y
CONFIG_DEBUG_PER_CPU_MAPS=y
CONFIG_HAVE_ARCH_KASAN=y
CONFIG_HAVE_ARCH_KASAN_VMALLOC=y
CONFIG_CC_HAS_KASAN_GENERIC=y
CONFIG_CC_HAS_WORKING_NOSANITIZE_ADDRESS=y
CONFIG_KASAN=y
CONFIG_KASAN_GENERIC=y
CONFIG_KASAN_OUTLINE=y
# CONFIG_KASAN_INLINE is not set
CONFIG_KASAN_STACK=y
CONFIG_KASAN_VMALLOC=y
CONFIG_KASAN_KUNIT_TEST=y
CONFIG_KASAN_MODULE_TEST=m
CONFIG_HAVE_ARCH_KFENCE=y
CONFIG_KFENCE=y
CONFIG_KFENCE_SAMPLE_INTERVAL=100
CONFIG_KFENCE_NUM_OBJECTS=255
CONFIG_KFENCE_DEFERRABLE=y
CONFIG_KFENCE_STATIC_KEYS=y
CONFIG_KFENCE_STRESS_TEST_FAULTS=0
CONFIG_KFENCE_KUNIT_TEST=y
CONFIG_HAVE_ARCH_KMSAN=y
# end of Memory Debugging

CONFIG_DEBUG_SHIRQ=y

#
# Debug Oops, Lockups and Hangs
#
CONFIG_PANIC_ON_OOPS=y
CONFIG_PANIC_ON_OOPS_VALUE=1
CONFIG_PANIC_TIMEOUT=0
CONFIG_LOCKUP_DETECTOR=y
CONFIG_SOFTLOCKUP_DETECTOR=y
CONFIG_BOOTPARAM_SOFTLOCKUP_PANIC=y
CONFIG_HARDLOCKUP_DETECTOR_PERF=y
CONFIG_HARDLOCKUP_CHECK_TIMESTAMP=y
CONFIG_HARDLOCKUP_DETECTOR=y
CONFIG_BOOTPARAM_HARDLOCKUP_PANIC=y
CONFIG_DETECT_HUNG_TASK=y
CONFIG_DEFAULT_HUNG_TASK_TIMEOUT=120
CONFIG_BOOTPARAM_HUNG_TASK_PANIC=y
CONFIG_WQ_WATCHDOG=y
CONFIG_TEST_LOCKUP=m
# end of Debug Oops, Lockups and Hangs

#
# Scheduler Debugging
#
CONFIG_SCHED_DEBUG=y
CONFIG_SCHED_INFO=y
CONFIG_SCHEDSTATS=y
# end of Scheduler Debugging

CONFIG_DEBUG_TIMEKEEPING=y
CONFIG_DEBUG_PREEMPT=y

#
# Lock Debugging (spinlocks, mutexes, etc...)
#
CONFIG_LOCK_DEBUGGING_SUPPORT=y
CONFIG_PROVE_LOCKING=y
CONFIG_PROVE_RAW_LOCK_NESTING=y
CONFIG_LOCK_STAT=y
CONFIG_DEBUG_RT_MUTEXES=y
CONFIG_DEBUG_SPINLOCK=y
CONFIG_DEBUG_MUTEXES=y
CONFIG_DEBUG_WW_MUTEX_SLOWPATH=y
CONFIG_DEBUG_RWSEMS=y
CONFIG_DEBUG_LOCK_ALLOC=y
CONFIG_LOCKDEP=y
CONFIG_LOCKDEP_BITS=15
CONFIG_LOCKDEP_CHAINS_BITS=16
CONFIG_LOCKDEP_STACK_TRACE_BITS=19
CONFIG_LOCKDEP_STACK_TRACE_HASH_BITS=14
CONFIG_LOCKDEP_CIRCULAR_QUEUE_BITS=12
CONFIG_DEBUG_LOCKDEP=y
CONFIG_DEBUG_ATOMIC_SLEEP=y
CONFIG_DEBUG_LOCKING_API_SELFTESTS=y
CONFIG_LOCK_TORTURE_TEST=y
CONFIG_WW_MUTEX_SELFTEST=y
CONFIG_SCF_TORTURE_TEST=y
CONFIG_CSD_LOCK_WAIT_DEBUG=y
# end of Lock Debugging (spinlocks, mutexes, etc...)

CONFIG_TRACE_IRQFLAGS=y
CONFIG_TRACE_IRQFLAGS_NMI=y
CONFIG_DEBUG_IRQFLAGS=y
CONFIG_STACKTRACE=y
CONFIG_WARN_ALL_UNSEEDED_RANDOM=y
CONFIG_DEBUG_KOBJECT=y
CONFIG_DEBUG_KOBJECT_RELEASE=y

#
# Debug kernel data structures
#
CONFIG_DEBUG_LIST=y
CONFIG_DEBUG_PLIST=y
CONFIG_DEBUG_SG=y
CONFIG_DEBUG_NOTIFIERS=y
CONFIG_BUG_ON_DATA_CORRUPTION=y
CONFIG_DEBUG_MAPLE_TREE=y
# end of Debug kernel data structures

CONFIG_DEBUG_CREDENTIALS=y

#
# RCU Debugging
#
CONFIG_PROVE_RCU=y
CONFIG_PROVE_RCU_LIST=y
CONFIG_TORTURE_TEST=y
CONFIG_RCU_SCALE_TEST=y
CONFIG_RCU_TORTURE_TEST=y
CONFIG_RCU_REF_SCALE_TEST=y
CONFIG_RCU_CPU_STALL_TIMEOUT=21
CONFIG_RCU_EXP_CPU_STALL_TIMEOUT=0
CONFIG_RCU_TRACE=y
CONFIG_RCU_EQS_DEBUG=y
# end of RCU Debugging

CONFIG_DEBUG_WQ_FORCE_RR_CPU=y
CONFIG_CPU_HOTPLUG_STATE_CONTROL=y
CONFIG_LATENCYTOP=y
CONFIG_USER_STACKTRACE_SUPPORT=y
CONFIG_NOP_TRACER=y
CONFIG_HAVE_RETHOOK=y
CONFIG_RETHOOK=y
CONFIG_HAVE_FUNCTION_TRACER=y
CONFIG_HAVE_FUNCTION_GRAPH_TRACER=y
CONFIG_HAVE_DYNAMIC_FTRACE=y
CONFIG_HAVE_DYNAMIC_FTRACE_WITH_REGS=y
CONFIG_HAVE_DYNAMIC_FTRACE_WITH_DIRECT_CALLS=y
CONFIG_HAVE_DYNAMIC_FTRACE_WITH_ARGS=y
CONFIG_HAVE_FTRACE_MCOUNT_RECORD=y
CONFIG_HAVE_SYSCALL_TRACEPOINTS=y
CONFIG_HAVE_FENTRY=y
CONFIG_HAVE_OBJTOOL_MCOUNT=y
CONFIG_HAVE_C_RECORDMCOUNT=y
CONFIG_HAVE_BUILDTIME_MCOUNT_SORT=y
CONFIG_BUILDTIME_MCOUNT_SORT=y
CONFIG_TRACER_MAX_TRACE=y
CONFIG_TRACE_CLOCK=y
CONFIG_RING_BUFFER=y
CONFIG_EVENT_TRACING=y
CONFIG_CONTEXT_SWITCH_TRACER=y
CONFIG_RING_BUFFER_ALLOW_SWAP=y
CONFIG_PREEMPTIRQ_TRACEPOINTS=y
CONFIG_TRACING=y
CONFIG_GENERIC_TRACER=y
CONFIG_TRACING_SUPPORT=y
CONFIG_FTRACE=y
CONFIG_BOOTTIME_TRACING=y
CONFIG_FUNCTION_TRACER=y
CONFIG_FUNCTION_GRAPH_TRACER=y
CONFIG_DYNAMIC_FTRACE=y
CONFIG_DYNAMIC_FTRACE_WITH_REGS=y
CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS=y
CONFIG_DYNAMIC_FTRACE_WITH_ARGS=y
CONFIG_FPROBE=y
CONFIG_FUNCTION_PROFILER=y
CONFIG_STACK_TRACER=y
CONFIG_TRACE_PREEMPT_TOGGLE=y
CONFIG_IRQSOFF_TRACER=y
CONFIG_PREEMPT_TRACER=y
CONFIG_SCHED_TRACER=y
CONFIG_HWLAT_TRACER=y
CONFIG_OSNOISE_TRACER=y
CONFIG_TIMERLAT_TRACER=y
CONFIG_MMIOTRACE=y
CONFIG_FTRACE_SYSCALLS=y
CONFIG_TRACER_SNAPSHOT=y
CONFIG_TRACER_SNAPSHOT_PER_CPU_SWAP=y
CONFIG_BRANCH_PROFILE_NONE=y
# CONFIG_PROFILE_ANNOTATED_BRANCHES is not set
CONFIG_BLK_DEV_IO_TRACE=y
CONFIG_KPROBE_EVENTS=y
CONFIG_KPROBE_EVENTS_ON_NOTRACE=y
CONFIG_UPROBE_EVENTS=y
CONFIG_BPF_EVENTS=y
CONFIG_DYNAMIC_EVENTS=y
CONFIG_PROBE_EVENTS=y
CONFIG_BPF_KPROBE_OVERRIDE=y
CONFIG_FTRACE_MCOUNT_RECORD=y
CONFIG_FTRACE_MCOUNT_USE_CC=y
CONFIG_TRACING_MAP=y
CONFIG_SYNTH_EVENTS=y
CONFIG_HIST_TRIGGERS=y
CONFIG_TRACE_EVENT_INJECT=y
CONFIG_TRACEPOINT_BENCHMARK=y
CONFIG_RING_BUFFER_BENCHMARK=y
CONFIG_TRACE_EVAL_MAP_FILE=y
CONFIG_FTRACE_RECORD_RECURSION=y
CONFIG_FTRACE_RECORD_RECURSION_SIZE=128
CONFIG_RING_BUFFER_RECORD_RECURSION=y
CONFIG_GCOV_PROFILE_FTRACE=y
CONFIG_FTRACE_SELFTEST=y
CONFIG_FTRACE_STARTUP_TEST=y
CONFIG_EVENT_TRACE_STARTUP_TEST=y
CONFIG_EVENT_TRACE_TEST_SYSCALLS=y
CONFIG_FTRACE_SORT_STARTUP_TEST=y
CONFIG_RING_BUFFER_STARTUP_TEST=y
CONFIG_RING_BUFFER_VALIDATE_TIME_DELTAS=y
CONFIG_MMIOTRACE_TEST=m
CONFIG_PREEMPTIRQ_DELAY_TEST=m
CONFIG_SYNTH_EVENT_GEN_TEST=y
CONFIG_KPROBE_EVENT_GEN_TEST=y
CONFIG_HIST_TRIGGERS_DEBUG=y
CONFIG_DA_MON_EVENTS=y
CONFIG_DA_MON_EVENTS_IMPLICIT=y
CONFIG_DA_MON_EVENTS_ID=y
CONFIG_RV=y
CONFIG_RV_MON_WIP=y
CONFIG_RV_MON_WWNR=y
CONFIG_RV_REACTORS=y
CONFIG_RV_REACT_PRINTK=y
CONFIG_RV_REACT_PANIC=y
CONFIG_PROVIDE_OHCI1394_DMA_INIT=y
CONFIG_SAMPLES=y
CONFIG_SAMPLE_AUXDISPLAY=y
CONFIG_SAMPLE_TRACE_EVENTS=m
CONFIG_SAMPLE_TRACE_CUSTOM_EVENTS=m
CONFIG_SAMPLE_TRACE_PRINTK=m
CONFIG_SAMPLE_FTRACE_DIRECT=m
CONFIG_SAMPLE_FTRACE_DIRECT_MULTI=m
CONFIG_SAMPLE_TRACE_ARRAY=m
CONFIG_SAMPLE_KOBJECT=y
CONFIG_SAMPLE_KPROBES=m
CONFIG_SAMPLE_KRETPROBES=m
CONFIG_SAMPLE_HW_BREAKPOINT=m
CONFIG_SAMPLE_FPROBE=m
CONFIG_SAMPLE_KFIFO=m
CONFIG_SAMPLE_KDB=m
CONFIG_SAMPLE_RPMSG_CLIENT=m
CONFIG_SAMPLE_LIVEPATCH=m
CONFIG_SAMPLE_CONFIGFS=m
CONFIG_SAMPLE_CONNECTOR=m
CONFIG_SAMPLE_FANOTIFY_ERROR=y
CONFIG_SAMPLE_HIDRAW=y
CONFIG_SAMPLE_LANDLOCK=y
CONFIG_SAMPLE_PIDFD=y
CONFIG_SAMPLE_SECCOMP=y
CONFIG_SAMPLE_TIMER=y
CONFIG_SAMPLE_UHID=y
CONFIG_SAMPLE_VFIO_MDEV_MTTY=m
CONFIG_SAMPLE_VFIO_MDEV_MDPY=m
CONFIG_SAMPLE_VFIO_MDEV_MDPY_FB=m
CONFIG_SAMPLE_VFIO_MDEV_MBOCHS=m
CONFIG_SAMPLE_ANDROID_BINDERFS=y
CONFIG_SAMPLE_VFS=y
CONFIG_SAMPLE_INTEL_MEI=y
CONFIG_SAMPLE_WATCHDOG=y
CONFIG_SAMPLE_WATCH_QUEUE=y
CONFIG_HAVE_SAMPLE_FTRACE_DIRECT=y
CONFIG_HAVE_SAMPLE_FTRACE_DIRECT_MULTI=y
CONFIG_ARCH_HAS_DEVMEM_IS_ALLOWED=y
CONFIG_STRICT_DEVMEM=y
CONFIG_IO_STRICT_DEVMEM=y

#
# x86 Debugging
#
CONFIG_EARLY_PRINTK_USB=y
CONFIG_X86_VERBOSE_BOOTUP=y
CONFIG_EARLY_PRINTK=y
CONFIG_EARLY_PRINTK_DBGP=y
CONFIG_EARLY_PRINTK_USB_XDBC=y
CONFIG_EFI_PGT_DUMP=y
CONFIG_DEBUG_TLBFLUSH=y
CONFIG_IOMMU_DEBUG=y
CONFIG_IOMMU_LEAK=y
CONFIG_HAVE_MMIOTRACE_SUPPORT=y
# CONFIG_X86_DECODER_SELFTEST is not set
CONFIG_IO_DELAY_0X80=y
# CONFIG_IO_DELAY_0XED is not set
# CONFIG_IO_DELAY_UDELAY is not set
# CONFIG_IO_DELAY_NONE is not set
CONFIG_DEBUG_BOOT_PARAMS=y
CONFIG_CPA_DEBUG=y
CONFIG_DEBUG_ENTRY=y
CONFIG_DEBUG_NMI_SELFTEST=y
CONFIG_X86_DEBUG_FPU=y
CONFIG_PUNIT_ATOM_DEBUG=y
CONFIG_UNWINDER_ORC=y
# CONFIG_UNWINDER_FRAME_POINTER is not set
# end of x86 Debugging

#
# Kernel Testing and Coverage
#
CONFIG_KUNIT=y
CONFIG_KUNIT_DEBUGFS=y
CONFIG_KUNIT_TEST=y
CONFIG_KUNIT_EXAMPLE_TEST=y
CONFIG_KUNIT_ALL_TESTS=y
CONFIG_NOTIFIER_ERROR_INJECTION=y
CONFIG_PM_NOTIFIER_ERROR_INJECT=y
CONFIG_OF_RECONFIG_NOTIFIER_ERROR_INJECT=y
CONFIG_NETDEV_NOTIFIER_ERROR_INJECT=y
CONFIG_FUNCTION_ERROR_INJECTION=y
CONFIG_FAULT_INJECTION=y
CONFIG_FAILSLAB=y
CONFIG_FAIL_PAGE_ALLOC=y
CONFIG_FAULT_INJECTION_USERCOPY=y
CONFIG_FAIL_MAKE_REQUEST=y
CONFIG_FAIL_IO_TIMEOUT=y
CONFIG_FAIL_FUTEX=y
CONFIG_FAULT_INJECTION_DEBUG_FS=y
CONFIG_FAIL_FUNCTION=y
CONFIG_FAIL_MMC_REQUEST=y
CONFIG_FAIL_SUNRPC=y
CONFIG_FAULT_INJECTION_STACKTRACE_FILTER=y
CONFIG_ARCH_HAS_KCOV=y
CONFIG_CC_HAS_SANCOV_TRACE_PC=y
CONFIG_KCOV=y
CONFIG_KCOV_ENABLE_COMPARISONS=y
CONFIG_KCOV_INSTRUMENT_ALL=y
CONFIG_KCOV_IRQ_AREA_SIZE=0x40000
CONFIG_RUNTIME_TESTING_MENU=y
CONFIG_LKDTM=y
CONFIG_CPUMASK_KUNIT_TEST=y
CONFIG_TEST_LIST_SORT=y
CONFIG_TEST_MIN_HEAP=y
CONFIG_TEST_SORT=y
CONFIG_TEST_DIV64=y
CONFIG_KPROBES_SANITY_TEST=y
CONFIG_FPROBE_SANITY_TEST=y
CONFIG_BACKTRACE_SELF_TEST=y
CONFIG_TEST_REF_TRACKER=y
CONFIG_RBTREE_TEST=y
CONFIG_REED_SOLOMON_TEST=y
CONFIG_INTERVAL_TREE_TEST=y
CONFIG_PERCPU_TEST=m
CONFIG_ATOMIC64_SELFTEST=y
CONFIG_ASYNC_RAID6_TEST=y
CONFIG_TEST_HEXDUMP=y
CONFIG_STRING_SELFTEST=y
CONFIG_TEST_STRING_HELPERS=y
CONFIG_TEST_STRSCPY=y
CONFIG_TEST_KSTRTOX=y
CONFIG_TEST_PRINTF=y
CONFIG_TEST_SCANF=y
CONFIG_TEST_BITMAP=y
CONFIG_TEST_UUID=y
CONFIG_TEST_XARRAY=y
CONFIG_TEST_RHASHTABLE=y
CONFIG_TEST_SIPHASH=y
CONFIG_TEST_IDA=y
CONFIG_TEST_PARMAN=y
CONFIG_TEST_LKM=m
CONFIG_TEST_BITOPS=m
CONFIG_TEST_VMALLOC=m
CONFIG_TEST_USER_COPY=m
CONFIG_TEST_BPF=m
CONFIG_TEST_BLACKHOLE_DEV=m
CONFIG_FIND_BIT_BENCHMARK=y
CONFIG_TEST_FIRMWARE=y
CONFIG_TEST_SYSCTL=y
CONFIG_BITFIELD_KUNIT=y
CONFIG_HASH_KUNIT_TEST=y
CONFIG_RESOURCE_KUNIT_TEST=y
CONFIG_SYSCTL_KUNIT_TEST=y
CONFIG_LIST_KUNIT_TEST=y
CONFIG_LINEAR_RANGES_TEST=y
CONFIG_CMDLINE_KUNIT_TEST=y
CONFIG_BITS_TEST=y
CONFIG_SLUB_KUNIT_TEST=y
CONFIG_RATIONAL_KUNIT_TEST=y
CONFIG_MEMCPY_KUNIT_TEST=y
CONFIG_OVERFLOW_KUNIT_TEST=y
CONFIG_STACKINIT_KUNIT_TEST=y
CONFIG_TEST_UDELAY=y
CONFIG_TEST_STATIC_KEYS=m
CONFIG_TEST_KMOD=m
CONFIG_TEST_DEBUG_VIRTUAL=y
CONFIG_TEST_MEMCAT_P=y
CONFIG_TEST_LIVEPATCH=m
CONFIG_TEST_OBJAGG=y
CONFIG_TEST_MEMINIT=y
CONFIG_TEST_HMM=y
CONFIG_TEST_FREE_PAGES=y
CONFIG_TEST_CLOCKSOURCE_WATCHDOG=y
CONFIG_ARCH_USE_MEMTEST=y
CONFIG_MEMTEST=y
CONFIG_HYPERV_TESTING=y
# end of Kernel Testing and Coverage
# end of Kernel hacking

--0Z4F7SWuvvF4NXmZ--
