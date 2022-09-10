Return-Path: <kasan-dev+bncBC4LXIPCY4NRBH5S6GMAMGQEGPBQGZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 37EC65B45AE
	for <lists+kasan-dev@lfdr.de>; Sat, 10 Sep 2022 11:30:08 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id bg2-20020a05600c3c8200b003b33080cff8sf395690wmb.0
        for <lists+kasan-dev@lfdr.de>; Sat, 10 Sep 2022 02:30:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662802208; cv=pass;
        d=google.com; s=arc-20160816;
        b=OLpcqxWpNWD4YvP5W5qSVVXvt7bbx7wGlRoKVuy/23Df0xZbczYUFZLyALyYF9cuJE
         eH7CbnM95Ra44Ge6MaTYD18khiqwitWrwHyK9pTkudiiVKVsSNr8WSRtZRLLwasQcNck
         zDowmeYP9HjkZH1v1+pA3gpCBixbTlq/Vq42waOliSvlr/lvoIeFVFFoOwZbVb+NmmoB
         zzo987NePOlSvVt4s1FvyKynlEr06DQ4td6XwU3oYzJW52yXYqnBcaWLz/2vwKy0QkHe
         t5XSYufBeGlLsMdvKqLGSxGeLUBig6GowEE+CP65sgFfKxHNIgXHrL43xyuk0uWbo0UN
         JIvg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=b+dwkuRQAaQD1zhMdktxgIOjLbtTRselJyFoCJqWPsg=;
        b=NaoG7k2JKp1VpIBFHWcG6Zy6Oaotp7CyHvIjYcg2shS3dn78igrh5IBsG1NzC3KgdX
         5qtQiYo+JUdLH5XK9+dE0yOCsGCEwoRPCNtEnADwp2JqQKLnrSenQbYTE3nGLwxR7zfN
         /cVhCah0fdjUKoUwpvLWb2XvvxU5l5sIAv08LZtFK5mBWLmpiQks8t//QrHozv8ja9j2
         d7jNDTStOTbPq/gGGOvbLuBWPFPSugSewmVHQKWrD508r1s8ehXKp5qtNtFp2GXkARF9
         fQ3zDJoe1MTCfYXGSfK+vP6p/dtyyWdibJML3ObsttRXeGXsEx+eKu9I27Iq56IuEYB7
         oBzQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=bxZKvCj0;
       spf=pass (google.com: domain of lkp@intel.com designates 192.55.52.151 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=b+dwkuRQAaQD1zhMdktxgIOjLbtTRselJyFoCJqWPsg=;
        b=FhhZEM83giCrIE2DDyCVx80IyfD/yO17s3qs2Otk2ly5k9g+3Vu1XDI4acO3Efwmxk
         LQ7aR6oOefi4FmfklZaxjrmzzvbsitWjpth2GkvaGDYduIfUbkJTO1yqMZXsnf4grcGm
         BTCO7/pLRM9lYWjkQaQemPVgCsF5eHebo2ZK4jNFabeMHS96HPUo0MVzxvSgsimMy7mm
         69jAmcj+CbBLXkya9WJl+M39jFMDH+9+l8R7Q2xzW6lJY42f4JSj78OJCnkIfxYDLiHr
         FkWIrWZjC3m89tBexyOhNYMero+vuj0D/xUYUOS+OyLUEMVRM/GZGegtR0jHIookNo4x
         othg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=b+dwkuRQAaQD1zhMdktxgIOjLbtTRselJyFoCJqWPsg=;
        b=p5gERw25+xm+N6oQpkmq9G5GaOHAXJTftfoX7joiOvFSJi5M0jr4zp3fe60Tjl9qK7
         BdfDr/C/+puAWyaPtEoRZI/nxO/JO5ADCin2v64L4NFuA5cdgAtJydfazlCjAP4qqscg
         GwLyk87k6fC5wnvroEpKQjH3RjllXiMyblgMpQNTSIFFnnjkQunGn0/YevkQpWGLkxsZ
         etOdNPX3wVlx3iT2ejytEHilvtnF+ttDgyXLAooYr1Sd6A1it3/2WAP5svFRPXmN3yCj
         s25AQOu5aMLXZKbZBmNSrny/CCa5UasV6ZtVXpbp87CHBLzFvz2jfqiw380yveF86s6P
         +wZw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo3w9Syaf64FLY+asFT9Uobimw9ju75qqYaMFGY7Ot2CkLnAkI/h
	VKHxdKHG7qNhqR+d4/qtZwo=
X-Google-Smtp-Source: AA6agR7Y7gI2qzCPimME0fARrgvrlkIlkHh12RKM0zrU7MG8T6sC0Bd9kSW3CXCj2NN0d4qqMTVrDg==
X-Received: by 2002:a05:600c:430c:b0:3a6:26e:88e8 with SMTP id p12-20020a05600c430c00b003a6026e88e8mr7745039wme.48.1662802207839;
        Sat, 10 Sep 2022 02:30:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:ce96:0:b0:3a5:1ad:8654 with SMTP id q22-20020a7bce96000000b003a501ad8654ls2271224wmj.2.-pod-control-gmail;
 Sat, 10 Sep 2022 02:30:06 -0700 (PDT)
X-Received: by 2002:a05:600c:2043:b0:3b3:c84c:ca33 with SMTP id p3-20020a05600c204300b003b3c84cca33mr4639733wmg.15.1662802206532;
        Sat, 10 Sep 2022 02:30:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662802206; cv=none;
        d=google.com; s=arc-20160816;
        b=RUSxXWzAItoySdy6gZHulJzrj3ZuquEg+3devWVQ91umgHtcwLaHuZWqHtOQSQCaLX
         QR1zKHy5+He//CyM6AJ4uVGgUfjxXYSdW8k2gkRXINsqzivquioQEH20ghNFhj26KCo/
         CWFaHqZC4RjdZo4YNCRcOwF9jwTgKhXysHxNWsxibi9sY6R/K7q/80kEt2g94Vz85a65
         H1ZDAV3/nTp2CPZWGzVw66xXRvhF/BhpsLXUXVuxvOgt+8IHSq2Mf83BZmnzQrb6V3Km
         6RugR5sYGvwR1G5XyFySHS4TwjkFN4k+oTzGrR/9IjwFLPjK9AB/MmRjiwbkW4ImqLdo
         I5+A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=ldt92b2eAIkPqAEfTE9jn8vW/dqoxD8jMb1KOaUcRaw=;
        b=nwvMg+pfmp3PVipY05dlRIzJThMnoHfyy1WyRDr8MRvOvJKQdw66+l0JDBi2Qy2s4+
         g0anSpHr6Gr6MA/8UvQ++IExFREeHO8wy+CgEmvSS5JHZQ8k0a9DWuuwiQOtRKT1L8JS
         9p8B/2YtSZ7RFcPYeusJ/BQjSnci/ciINWePn+HYwxwsqQqO3SaljlcPeb05B1U0jLLO
         m2iNrVFmBgIbcX/NUQ6ZkPHE+4hwnILKS7+ni2l/By7zTYOFAnqruP698HMTWF1TFmX8
         V88XW7H/VJAz8FKi5Oe1Y+xAd8I54jKv9cPQe89xCvTWYXSMDQSB8L+bFFha6SX3h42M
         V6Sw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=bxZKvCj0;
       spf=pass (google.com: domain of lkp@intel.com designates 192.55.52.151 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga17.intel.com (mga17.intel.com. [192.55.52.151])
        by gmr-mx.google.com with ESMTPS id f21-20020a7bcc15000000b003a5ce2af2c7si152860wmh.1.2022.09.10.02.30.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 10 Sep 2022 02:30:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 192.55.52.151 as permitted sender) client-ip=192.55.52.151;
X-IronPort-AV: E=McAfee;i="6500,9779,10465"; a="278021354"
X-IronPort-AV: E=Sophos;i="5.93,305,1654585200"; 
   d="scan'208";a="278021354"
Received: from fmsmga005.fm.intel.com ([10.253.24.32])
  by fmsmga107.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 10 Sep 2022 02:29:54 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="5.93,305,1654585200"; 
   d="scan'208";a="944057456"
Received: from lkp-server02.sh.intel.com (HELO b2938d2e5c5a) ([10.239.97.151])
  by fmsmga005.fm.intel.com with ESMTP; 10 Sep 2022 02:29:50 -0700
Received: from kbuild by b2938d2e5c5a with local (Exim 4.96)
	(envelope-from <lkp@intel.com>)
	id 1oWwoA-0002MF-0r;
	Sat, 10 Sep 2022 09:29:50 +0000
Date: Sat, 10 Sep 2022 17:29:26 +0800
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
Subject: Re: [PATCH] kasan: also display registers for reports from HW
 exceptions
Message-ID: <202209101749.RYRMIdqE-lkp@intel.com>
References: <20220910052426.943376-1-pcc@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220910052426.943376-1-pcc@google.com>
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=bxZKvCj0;       spf=pass
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

Hi Peter,

Thank you for the patch! Perhaps something to improve:

[auto build test WARNING on next-20220909]
[cannot apply to arm64/for-next/core linus/master v6.0-rc4 v6.0-rc3 v6.0-rc2 v6.0-rc4]
[If your patch is applied to the wrong git tree, kindly drop us a note.
And when submitting patch, we suggest to use '--base' as documented in
https://git-scm.com/docs/git-format-patch#_base_tree_information]

url:    https://github.com/intel-lab-lkp/linux/commits/Peter-Collingbourne/kasan-also-display-registers-for-reports-from-HW-exceptions/20220910-132721
base:    9a82ccda91ed2b40619cb3c10d446ae1f97bab6e
config: x86_64-allyesconfig (https://download.01.org/0day-ci/archive/20220910/202209101749.RYRMIdqE-lkp@intel.com/config)
compiler: gcc-11 (Debian 11.3.0-5) 11.3.0
reproduce (this is a W=1 build):
        # https://github.com/intel-lab-lkp/linux/commit/2140392d32582f62b922eaf4d1824e5a7838b420
        git remote add linux-review https://github.com/intel-lab-lkp/linux
        git fetch --no-tags linux-review Peter-Collingbourne/kasan-also-display-registers-for-reports-from-HW-exceptions/20220910-132721
        git checkout 2140392d32582f62b922eaf4d1824e5a7838b420
        # save the config file
        mkdir build_dir && cp config build_dir/.config
        make W=1 O=build_dir ARCH=x86_64 SHELL=/bin/bash

If you fix the issue, kindly add following tag where applicable
Reported-by: kernel test robot <lkp@intel.com>

All warnings (new ones prefixed by >>):

>> vmlinux.o: warning: objtool: .altinstr_replacement+0x2d02: redundant UACCESS disable
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
02ac      2ac:	e9 00 00 00 00       	jmp    2b1 <.altinstr_replacement+0x2b1>	2ad: R_X86_64_PC32	.init.text+0xc2e3
02b1      2b1:	e9 00 00 00 00       	jmp    2b6 <.altinstr_replacement+0x2b6>	2b2: R_X86_64_PC32	.init.text+0xc39b
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
033d      33d:	e9 00 00 00 00       	jmp    342 <.altinstr_replacement+0x342>	33e: R_X86_64_PC32	.text+0x13965
0342      342:	f3 48 0f b8 c7       	popcnt %rdi,%rax
0347      347:	f3 48 0f b8 c7       	popcnt %rdi,%rax
034c      34c:	e9 00 00 00 00       	jmp    351 <.altinstr_replacement+0x351>	34d: R_X86_64_PC32	.text+0x18371
0351      351:	e9 00 00 00 00       	jmp    356 <.altinstr_replacement+0x356>	352: R_X86_64_PC32	.init.text+0xe8da
0356      356:	0f ae e8             	lfence
0359      359:	0f 31                	rdtsc
035b      35b:	0f 01 f9             	rdtscp
035e      35e:	0f ae e8             	lfence
0361      361:	0f 31                	rdtsc
0363      363:	0f 01 f9             	rdtscp
0366      366:	0f ae e8             	lfence
0369      369:	0f 31                	rdtsc
036b      36b:	0f 01 f9             	rdtscp
036e      36e:	f3 48 0f b8 c7       	popcnt %rdi,%rax
0373      373:	f3 48 0f b8 c7       	popcnt %rdi,%rax
0378      378:	9c                   	pushf
0379      379:	58                   	pop    %rax
037a      37a:	fb                   	sti
037b      37b:	9c                   	pushf
037c      37c:	58                   	pop    %rax
037d      37d:	fa                   	cli
037e      37e:	9c                   	pushf
037f      37f:	58                   	pop    %rax
0380      380:	fa                   	cli
0381      381:	9c                   	pushf
0382      382:	58                   	pop    %rax
0383      383:	fa                   	cli
0384      384:	9c                   	pushf
0385      385:	58                   	pop    %rax
0386      386:	fb                   	sti
0387      387:	e9 00 00 00 00       	jmp    38c <.altinstr_replacement+0x38c>	388: R_X86_64_PC32	.init.text+0x1403b
038c      38c:	e9 00 00 00 00       	jmp    391 <.altinstr_replacement+0x391>	38d: R_X86_64_PC32	.text+0x3629d
0391      391:	e9 00 00 00 00       	jmp    396 <.altinstr_replacement+0x396>	392: R_X86_64_PC32	.text+0x362a8
0396      396:	e9 00 00 00 00       	jmp    39b <.altinstr_replacement+0x39b>	397: R_X86_64_PC32	.text+0x3632f
039b      39b:	e9 00 00 00 00       	jmp    3a0 <.altinstr_replacement+0x3a0>	39c: R_X86_64_PC32	.text+0x3633a
03a0      3a0:	e9 00 00 00 00       	jmp    3a5 <.altinstr_replacement+0x3a5>	3a1: R_X86_64_PC32	.text+0x36671
03a5      3a5:	e9 00 00 00 00       	jmp    3aa <.altinstr_replacement+0x3aa>	3a6: R_X86_64_PC32	.text+0x36f1e
03aa      3aa:	e9 00 00 00 00       	jmp    3af <.altinstr_replacement+0x3af>	3ab: R_X86_64_PC32	.text+0x376b0
03af      3af:	e9 00 00 00 00       	jmp    3b4 <.altinstr_replacement+0x3b4>	3b0: R_X86_64_PC32	.text+0x375ce
03b4      3b4:	e9 00 00 00 00       	jmp    3b9 <.altinstr_replacement+0x3b9>	3b5: R_X86_64_PC32	.text+0x37720
03b9      3b9:	e9 00 00 00 00       	jmp    3be <.altinstr_replacement+0x3be>	3ba: R_X86_64_PC32	.text+0x376a3
03be      3be:	e9 00 00 00 00       	jmp    3c3 <.altinstr_replacement+0x3c3>	3bf: R_X86_64_PC32	.text+0x37a79
03c3      3c3:	e9 00 00 00 00       	jmp    3c8 <.altinstr_replacement+0x3c8>	3c4: R_X86_64_PC32	.text+0x37b83
03c8      3c8:	e9 00 00 00 00       	jmp    3cd <.altinstr_replacement+0x3cd>	3c9: R_X86_64_PC32	.text+0x37b8e
03cd      3cd:	e9 00 00 00 00       	jmp    3d2 <.altinstr_replacement+0x3d2>	3ce: R_X86_64_PC32	.text+0x37c36
03d2      3d2:	e9 00 00 00 00       	jmp    3d7 <.altinstr_replacement+0x3d7>	3d3: R_X86_64_PC32	.text+0x37cf9
03d7      3d7:	e9 00 00 00 00       	jmp    3dc <.altinstr_replacement+0x3dc>	3d8: R_X86_64_PC32	.text+0x37d07
03dc      3dc:	e9 00 00 00 00       	jmp    3e1 <.altinstr_replacement+0x3e1>	3dd: R_X86_64_PC32	.text+0x37c36
03e1      3e1:	e9 00 00 00 00       	jmp    3e6 <.altinstr_replacement+0x3e6>	3e2: R_X86_64_PC32	.text+0x3877f
03e6      3e6:	e9 00 00 00 00       	jmp    3eb <.altinstr_replacement+0x3eb>	3e7: R_X86_64_PC32	.text+0x3880d
03eb      3eb:	e9 00 00 00 00       	jmp    3f0 <.altinstr_replacement+0x3f0>	3ec: R_X86_64_PC32	.text+0x38802
03f0      3f0:	e9 00 00 00 00       	jmp    3f5 <.altinstr_replacement+0x3f5>	3f1: R_X86_64_PC32	.text+0x387f7
03f5      3f5:	e9 00 00 00 00       	jmp    3fa <.altinstr_replacement+0x3fa>	3f6: R_X86_64_PC32	.text+0x38bf3
03fa      3fa:	e9 00 00 00 00       	jmp    3ff <.altinstr_replacement+0x3ff>	3fb: R_X86_64_PC32	.text+0x38db5
03ff      3ff:	e9 00 00 00 00       	jmp    404 <.altinstr_replacement+0x404>	400: R_X86_64_PC32	.text+0x38f7b
0404      404:	e9 00 00 00 00       	jmp    409 <.altinstr_replacement+0x409>	405: R_X86_64_PC32	.text+0x391ff
0409      409:	e9 00 00 00 00       	jmp    40e <.altinstr_replacement+0x40e>	40a: R_X86_64_PC32	.text+0x3948e
040e      40e:	e9 00 00 00 00       	jmp    413 <.altinstr_replacement+0x413>	40f: R_X86_64_PC32	.text+0x3a401
0413      413:	e9 00 00 00 00       	jmp    418 <.altinstr_replacement+0x418>	414: R_X86_64_PC32	.text+0x3a542
0418      418:	9c                   	pushf
0419      419:	58                   	pop    %rax
041a      41a:	fa                   	cli
041b      41b:	9c                   	pushf
041c      41c:	58                   	pop    %rax
041d      41d:	fb                   	sti
041e      41e:	9c                   	pushf
041f      41f:	58                   	pop    %rax
0420      420:	fa                   	cli
0421      421:	9c                   	pushf
0422      422:	58                   	pop    %rax
0423      423:	fb                   	sti
0424      424:	f3 0f b8 c7          	popcnt %edi,%eax
0428      428:	f3 48 0f b8 c7       	popcnt %rdi,%rax
042d      42d:	e9 00 00 00 00       	jmp    432 <.altinstr_replacement+0x432>	42e: R_X86_64_PC32	.text+0x67881
0432      432:	e9 00 00 00 00       	jmp    437 <.altinstr_replacement+0x437>	433: R_X86_64_PC32	.text+0x678db
0437      437:	e8 00 00 00 00       	call   43c <.altinstr_replacement+0x43c>	438: R_X86_64_PLT32	copy_user_generic_string-0x4
043c      43c:	e8 00 00 00 00       	call   441 <.altinstr_replacement+0x441>	43d: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
0441      441:	e8 00 00 00 00       	call   446 <.altinstr_replacement+0x446>	442: R_X86_64_PLT32	copy_user_generic_string-0x4
0446      446:	e8 00 00 00 00       	call   44b <.altinstr_replacement+0x44b>	447: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
044b      44b:	48 89 f8             	mov    %rdi,%rax
044e      44e:	e8 00 00 00 00       	call   453 <.altinstr_replacement+0x453>	44f: R_X86_64_PLT32	copy_user_generic_string-0x4
0453      453:	e8 00 00 00 00       	call   458 <.altinstr_replacement+0x458>	454: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
0458      458:	e8 00 00 00 00       	call   45d <.altinstr_replacement+0x45d>	459: R_X86_64_PLT32	copy_user_generic_string-0x4
045d      45d:	e8 00 00 00 00       	call   462 <.altinstr_replacement+0x462>	45e: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
0462      462:	48 89 f8             	mov    %rdi,%rax
0465      465:	e9 00 00 00 00       	jmp    46a <.altinstr_replacement+0x46a>	466: R_X86_64_PC32	.text+0x6f3c5
046a      46a:	e9 00 00 00 00       	jmp    46f <.altinstr_replacement+0x46f>	46b: R_X86_64_PC32	.text+0x6f40f
046f      46f:	48 89 f8             	mov    %rdi,%rax
0472      472:	49 be 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r14
047c      47c:	e9 00 00 00 00       	jmp    481 <.altinstr_replacement+0x481>	47d: R_X86_64_PC32	.text+0x7421a
0481      481:	e9 00 00 00 00       	jmp    486 <.altinstr_replacement+0x486>	482: R_X86_64_PC32	.text+0x74089
0486      486:	48 89 f8             	mov    %rdi,%rax
0489      489:	48 89 f8             	mov    %rdi,%rax
048c      48c:	48 89 f8             	mov    %rdi,%rax
048f      48f:	e8 00 00 00 00       	call   494 <.altinstr_replacement+0x494>	490: R_X86_64_PLT32	copy_user_generic_string-0x4
0494      494:	e8 00 00 00 00       	call   499 <.altinstr_replacement+0x499>	495: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
0499      499:	e9 00 00 00 00       	jmp    49e <.altinstr_replacement+0x49e>	49a: R_X86_64_PC32	.text+0x7b8bc
049e      49e:	e9 00 00 00 00       	jmp    4a3 <.altinstr_replacement+0x4a3>	49f: R_X86_64_PC32	.text+0x7b72b
04a3      4a3:	9c                   	pushf
04a4      4a4:	58                   	pop    %rax
04a5      4a5:	fa                   	cli
04a6      4a6:	9c                   	pushf
04a7      4a7:	58                   	pop    %rax
04a8      4a8:	fb                   	sti
04a9      4a9:	e9 00 00 00 00       	jmp    4ae <.altinstr_replacement+0x4ae>	4aa: R_X86_64_PC32	.text+0x88728
04ae      4ae:	e9 00 00 00 00       	jmp    4b3 <.altinstr_replacement+0x4b3>	4af: R_X86_64_PC32	.text+0x886d6
04b3      4b3:	e9 00 00 00 00       	jmp    4b8 <.altinstr_replacement+0x4b8>	4b4: R_X86_64_PC32	.text+0x884bb
04b8      4b8:	e9 00 00 00 00       	jmp    4bd <.altinstr_replacement+0x4bd>	4b9: R_X86_64_PC32	.text+0x8825b
04bd      4bd:	e9 00 00 00 00       	jmp    4c2 <.altinstr_replacement+0x4c2>	4be: R_X86_64_PC32	.text+0x88fa8
04c2      4c2:	e9 00 00 00 00       	jmp    4c7 <.altinstr_replacement+0x4c7>	4c3: R_X86_64_PC32	.text+0x8910a
04c7      4c7:	e9 00 00 00 00       	jmp    4cc <.altinstr_replacement+0x4cc>	4c8: R_X86_64_PC32	.text+0x895dd
04cc      4cc:	e9 00 00 00 00       	jmp    4d1 <.altinstr_replacement+0x4d1>	4cd: R_X86_64_PC32	.text+0x894db
04d1      4d1:	9c                   	pushf
04d2      4d2:	58                   	pop    %rax
04d3      4d3:	fa                   	cli
04d4      4d4:	9c                   	pushf
04d5      4d5:	58                   	pop    %rax
04d6      4d6:	fb                   	sti
04d7      4d7:	0f ae e8             	lfence
04da      4da:	0f 31                	rdtsc
04dc      4dc:	0f 01 f9             	rdtscp
04df      4df:	0f ae e8             	lfence
04e2      4e2:	0f 31                	rdtsc
04e4      4e4:	0f 01 f9             	rdtscp
04e7      4e7:	0f 09                	wbinvd
04e9      4e9:	0f 09                	wbinvd
04eb      4eb:	9c                   	pushf
04ec      4ec:	58                   	pop    %rax
04ed      4ed:	fa                   	cli
04ee      4ee:	9c                   	pushf
04ef      4ef:	58                   	pop    %rax
04f0      4f0:	fb                   	sti
04f1      4f1:	0f 01 cb             	stac
04f4      4f4:	0f ae e8             	lfence
04f7      4f7:	0f 01 cb             	stac
04fa      4fa:	0f ae e8             	lfence
04fd      4fd:	0f 01 cb             	stac
0500      500:	0f ae e8             	lfence
0503      503:	0f 01 ca             	clac
0506      506:	0f 01 cb             	stac
0509      509:	0f ae e8             	lfence
050c      50c:	0f 01 ca             	clac
050f      50f:	9c                   	pushf
0510      510:	58                   	pop    %rax
0511      511:	fa                   	cli
0512      512:	9c                   	pushf
0513      513:	58                   	pop    %rax
0514      514:	fb                   	sti
0515      515:	9c                   	pushf
0516      516:	58                   	pop    %rax
0517      517:	fb                   	sti
0518      518:	9c                   	pushf
0519      519:	58                   	pop    %rax
051a      51a:	fa                   	cli
051b      51b:	9c                   	pushf
051c      51c:	58                   	pop    %rax
051d      51d:	fb                   	sti
051e      51e:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
0528      528:	0f 01 cb             	stac
052b      52b:	0f ae e8             	lfence
052e      52e:	0f 01 ca             	clac
0531      531:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
053b      53b:	0f 01 cb             	stac
053e      53e:	0f ae e8             	lfence
0541      541:	0f 01 ca             	clac
0544      544:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
054e      54e:	0f 01 cb             	stac
0551      551:	0f ae e8             	lfence
0554      554:	e9 00 00 00 00       	jmp    559 <.altinstr_replacement+0x559>	555: R_X86_64_PC32	.text+0xc86a7
0559      559:	e9 00 00 00 00       	jmp    55e <.altinstr_replacement+0x55e>	55a: R_X86_64_PC32	.text+0xc86bf
055e      55e:	e9 00 00 00 00       	jmp    563 <.altinstr_replacement+0x563>	55f: R_X86_64_PC32	.text+0xc8c12
0563      563:	e9 00 00 00 00       	jmp    568 <.altinstr_replacement+0x568>	564: R_X86_64_PC32	.text+0xc8c12
0568      568:	e9 00 00 00 00       	jmp    56d <.altinstr_replacement+0x56d>	569: R_X86_64_PC32	.text+0xd1b18
056d      56d:	9c                   	pushf
056e      56e:	58                   	pop    %rax
056f      56f:	fa                   	cli
0570      570:	fb                   	sti
0571      571:	fb                   	sti
0572      572:	9c                   	pushf
0573      573:	58                   	pop    %rax
0574      574:	fa                   	cli
0575      575:	fb                   	sti
0576      576:	9c                   	pushf
0577      577:	58                   	pop    %rax
0578      578:	e8 00 00 00 00       	call   57d <.altinstr_replacement+0x57d>	579: R_X86_64_PLT32	__x86_indirect_thunk_r12-0x4
057d      57d:	0f ae e8             	lfence
0580      580:	41 ff d4             	call   *%r12
0583      583:	e8 00 00 00 00       	call   588 <.altinstr_replacement+0x588>	584: R_X86_64_PLT32	__x86_indirect_thunk_rsi-0x4
0588      588:	0f ae e8             	lfence
058b      58b:	ff d6                	call   *%rsi
058d      58d:	e8 00 00 00 00       	call   592 <.altinstr_replacement+0x592>	58e: R_X86_64_PLT32	__x86_indirect_thunk_r13-0x4
0592      592:	0f ae e8             	lfence
0595      595:	41 ff d5             	call   *%r13
0598      598:	e8 00 00 00 00       	call   59d <.altinstr_replacement+0x59d>	599: R_X86_64_PLT32	__x86_indirect_thunk_r13-0x4
059d      59d:	0f ae e8             	lfence
05a0      5a0:	41 ff d5             	call   *%r13
05a3      5a3:	e8 00 00 00 00       	call   5a8 <.altinstr_replacement+0x5a8>	5a4: R_X86_64_PLT32	__x86_indirect_thunk_rax-0x4
05a8      5a8:	0f ae e8             	lfence
05ab      5ab:	ff d0                	call   *%rax
05ad      5ad:	e8 00 00 00 00       	call   5b2 <.altinstr_replacement+0x5b2>	5ae: R_X86_64_PLT32	__x86_indirect_thunk_r13-0x4
05b2      5b2:	0f ae e8             	lfence
05b5      5b5:	41 ff d5             	call   *%r13
05b8      5b8:	f3 0f b8 c7          	popcnt %edi,%eax
05bc      5bc:	9c                   	pushf
05bd      5bd:	58                   	pop    %rax
05be      5be:	f3 0f b8 c7          	popcnt %edi,%eax
05c2      5c2:	f3 0f b8 c7          	popcnt %edi,%eax
05c6      5c6:	9c                   	pushf
05c7      5c7:	58                   	pop    %rax
05c8      5c8:	9c                   	pushf
05c9      5c9:	58                   	pop    %rax
05ca      5ca:	fa                   	cli
05cb      5cb:	9c                   	pushf
05cc      5cc:	58                   	pop    %rax
05cd      5cd:	fb                   	sti
05ce      5ce:	9c                   	pushf
05cf      5cf:	58                   	pop    %rax
05d0      5d0:	e9 00 00 00 00       	jmp    5d5 <.altinstr_replacement+0x5d5>	5d1: R_X86_64_PC32	.text+0x1192a8
05d5      5d5:	e9 00 00 00 00       	jmp    5da <.altinstr_replacement+0x5da>	5d6: R_X86_64_PC32	.text+0x11925e
05da      5da:	e9 00 00 00 00       	jmp    5df <.altinstr_replacement+0x5df>	5db: R_X86_64_PC32	.text+0x119a2d
05df      5df:	e9 00 00 00 00       	jmp    5e4 <.altinstr_replacement+0x5e4>	5e0: R_X86_64_PC32	.text+0x1199a9
05e4      5e4:	e9 00 00 00 00       	jmp    5e9 <.altinstr_replacement+0x5e9>	5e5: R_X86_64_PC32	.text+0x1192ff
05e9      5e9:	f3 48 0f b8 c7       	popcnt %rdi,%rax
05ee      5ee:	f3 48 0f b8 c7       	popcnt %rdi,%rax
05f3      5f3:	e9 00 00 00 00       	jmp    5f8 <.altinstr_replacement+0x5f8>	5f4: R_X86_64_PC32	.text+0x1300de
05f8      5f8:	48 89 f8             	mov    %rdi,%rax
05fb      5fb:	9c                   	pushf
05fc      5fc:	58                   	pop    %rax
05fd      5fd:	fa                   	cli
05fe      5fe:	0f 01 cb             	stac
0601      601:	0f ae e8             	lfence
0604      604:	0f 01 ca             	clac
0607      607:	0f 01 ca             	clac
060a      60a:	0f 01 cb             	stac
060d      60d:	0f ae e8             	lfence
0610      610:	0f 01 ca             	clac
0613      613:	0f 01 ca             	clac
0616      616:	0f 01 cb             	stac
0619      619:	0f ae e8             	lfence
061c      61c:	0f 01 ca             	clac
061f      61f:	0f 01 ca             	clac
0622      622:	fb                   	sti
0623      623:	48 89 f8             	mov    %rdi,%rax
0626      626:	9c                   	pushf
0627      627:	58                   	pop    %rax
0628      628:	fa                   	cli
0629      629:	e9 00 00 00 00       	jmp    62e <.altinstr_replacement+0x62e>	62a: R_X86_64_PC32	.text+0x142f1d
062e      62e:	9c                   	pushf
062f      62f:	58                   	pop    %rax
0630      630:	fb                   	sti
0631      631:	48 89 f8             	mov    %rdi,%rax
0634      634:	48 89 f8             	mov    %rdi,%rax
0637      637:	48 89 f8             	mov    %rdi,%rax
063a      63a:	9c                   	pushf
063b      63b:	58                   	pop    %rax
063c      63c:	fa                   	cli
063d      63d:	fb                   	sti
063e      63e:	e9 00 00 00 00       	jmp    643 <.altinstr_replacement+0x643>	63f: R_X86_64_PC32	.text+0x15f8c6
0643      643:	e9 00 00 00 00       	jmp    648 <.altinstr_replacement+0x648>	644: R_X86_64_PC32	.text+0x15f787
0648      648:	48 89 f8             	mov    %rdi,%rax
064b      64b:	e9 00 00 00 00       	jmp    650 <.altinstr_replacement+0x650>	64c: R_X86_64_PC32	.noinstr.text+0x1671
0650      650:	e8 00 00 00 00       	call   655 <.altinstr_replacement+0x655>	651: R_X86_64_PLT32	copy_user_generic_string-0x4
0655      655:	e8 00 00 00 00       	call   65a <.altinstr_replacement+0x65a>	656: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
065a      65a:	e8 00 00 00 00       	call   65f <.altinstr_replacement+0x65f>	65b: R_X86_64_PLT32	copy_user_generic_string-0x4
065f      65f:	e8 00 00 00 00       	call   664 <.altinstr_replacement+0x664>	660: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
0664      664:	e8 00 00 00 00       	call   669 <.altinstr_replacement+0x669>	665: R_X86_64_PLT32	copy_user_generic_string-0x4
0669      669:	e8 00 00 00 00       	call   66e <.altinstr_replacement+0x66e>	66a: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
066e      66e:	9c                   	pushf
066f      66f:	58                   	pop    %rax
0670      670:	fa                   	cli
0671      671:	9c                   	pushf
0672      672:	58                   	pop    %rax
0673      673:	fb                   	sti
0674      674:	9c                   	pushf
0675      675:	58                   	pop    %rax
0676      676:	fa                   	cli
0677      677:	9c                   	pushf
0678      678:	58                   	pop    %rax
0679      679:	fb                   	sti
067a      67a:	9c                   	pushf
067b      67b:	58                   	pop    %rax
067c      67c:	e9 00 00 00 00       	jmp    681 <.altinstr_replacement+0x681>	67d: R_X86_64_PC32	.text+0x180ea8
0681      681:	9c                   	pushf
0682      682:	58                   	pop    %rax
0683      683:	fa                   	cli
0684      684:	fb                   	sti
0685      685:	0f 30                	wrmsr
0687      687:	e8 00 00 00 00       	call   68c <.altinstr_replacement+0x68c>	688: R_X86_64_PLT32	copy_user_generic_string-0x4
068c      68c:	e8 00 00 00 00       	call   691 <.altinstr_replacement+0x691>	68d: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
0691      691:	0f 20 d8             	mov    %cr3,%rax
0694      694:	e9 00 00 00 00       	jmp    699 <.altinstr_replacement+0x699>	695: R_X86_64_PC32	.noinstr.text+0x1af2
0699      699:	e9 00 00 00 00       	jmp    69e <.altinstr_replacement+0x69e>	69a: R_X86_64_PC32	.noinstr.text+0x1afb
069e      69e:	0f ae e8             	lfence
06a1      6a1:	48 c7 c1 10 00 00 00 	mov    $0x10,%rcx
06a8      6a8:	e8 01 00 00 00       	call   6ae <.altinstr_replacement+0x6ae>
06ad      6ad:	cc                   	int3
06ae      6ae:	e8 01 00 00 00       	call   6b4 <.altinstr_replacement+0x6b4>
06b3      6b3:	cc                   	int3
06b4      6b4:	48 83 c4 10          	add    $0x10,%rsp
06b8      6b8:	48 ff c9             	dec    %rcx
06bb      6bb:	75 eb                	jne    6a8 <.altinstr_replacement+0x6a8>
06bd      6bd:	0f ae e8             	lfence
06c0      6c0:	e8 01 00 00 00       	call   6c6 <.altinstr_replacement+0x6c6>
06c5      6c5:	cc                   	int3
06c6      6c6:	48 83 c4 08          	add    $0x8,%rsp
06ca      6ca:	0f ae e8             	lfence
06cd      6cd:	9c                   	pushf
06ce      6ce:	58                   	pop    %rax
06cf      6cf:	fa                   	cli
06d0      6d0:	fb                   	sti
06d1      6d1:	fb                   	sti
06d2      6d2:	fb                   	sti
06d3      6d3:	9c                   	pushf
06d4      6d4:	58                   	pop    %rax
06d5      6d5:	fa                   	cli
06d6      6d6:	9c                   	pushf
06d7      6d7:	58                   	pop    %rax
06d8      6d8:	fb                   	sti
06d9      6d9:	9c                   	pushf
06da      6da:	58                   	pop    %rax
06db      6db:	fa                   	cli
06dc      6dc:	9c                   	pushf
06dd      6dd:	58                   	pop    %rax
06de      6de:	fb                   	sti
06df      6df:	e8 00 00 00 00       	call   6e4 <.altinstr_replacement+0x6e4>	6e0: R_X86_64_PLT32	copy_user_generic_string-0x4
06e4      6e4:	e8 00 00 00 00       	call   6e9 <.altinstr_replacement+0x6e9>	6e5: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
06e9      6e9:	e9 00 00 00 00       	jmp    6ee <.altinstr_replacement+0x6ee>	6ea: R_X86_64_PC32	.text.unlikely+0x1b3ab
06ee      6ee:	e9 00 00 00 00       	jmp    6f3 <.altinstr_replacement+0x6f3>	6ef: R_X86_64_PC32	.text+0x1e833e
06f3      6f3:	e9 00 00 00 00       	jmp    6f8 <.altinstr_replacement+0x6f8>	6f4: R_X86_64_PC32	.text+0x1e98a8
06f8      6f8:	e9 00 00 00 00       	jmp    6fd <.altinstr_replacement+0x6fd>	6f9: R_X86_64_PC32	.text+0x1e99e0
06fd      6fd:	e9 00 00 00 00       	jmp    702 <.altinstr_replacement+0x702>	6fe: R_X86_64_PC32	.text+0x1e9bb8
0702      702:	e8 00 00 00 00       	call   707 <.altinstr_replacement+0x707>	703: R_X86_64_PLT32	clear_page_rep-0x4
0707      707:	e8 00 00 00 00       	call   70c <.altinstr_replacement+0x70c>	708: R_X86_64_PLT32	clear_page_erms-0x4
070c      70c:	0f 30                	wrmsr
070e      70e:	e9 00 00 00 00       	jmp    713 <.altinstr_replacement+0x713>	70f: R_X86_64_PC32	.text+0x1edc2e
0713      713:	e9 00 00 00 00       	jmp    718 <.altinstr_replacement+0x718>	714: R_X86_64_PC32	.text+0x1ef866
0718      718:	e9 00 00 00 00       	jmp    71d <.altinstr_replacement+0x71d>	719: R_X86_64_PC32	.text+0x1efc60
071d      71d:	e9 00 00 00 00       	jmp    722 <.altinstr_replacement+0x722>	71e: R_X86_64_PC32	.text+0x1f1b33
0722      722:	e9 00 00 00 00       	jmp    727 <.altinstr_replacement+0x727>	723: R_X86_64_PC32	.text+0x1f6572
0727      727:	e9 00 00 00 00       	jmp    72c <.altinstr_replacement+0x72c>	728: R_X86_64_PC32	.text+0x1f65f1
072c      72c:	e9 00 00 00 00       	jmp    731 <.altinstr_replacement+0x731>	72d: R_X86_64_PC32	.text+0x1f97e1
0731      731:	e9 00 00 00 00       	jmp    736 <.altinstr_replacement+0x736>	732: R_X86_64_PC32	.text+0x1f9728
0736      736:	e9 00 00 00 00       	jmp    73b <.altinstr_replacement+0x73b>	737: R_X86_64_PC32	.text+0x1f9c1d
073b      73b:	48 c7 c0 10 00 00 00 	mov    $0x10,%rax
0742      742:	e8 01 00 00 00       	call   748 <.altinstr_replacement+0x748>
0747      747:	cc                   	int3
0748      748:	e8 01 00 00 00       	call   74e <.altinstr_replacement+0x74e>
074d      74d:	cc                   	int3
074e      74e:	48 83 c4 10          	add    $0x10,%rsp
0752      752:	48 ff c8             	dec    %rax
0755      755:	75 eb                	jne    742 <.altinstr_replacement+0x742>
0757      757:	0f ae e8             	lfence
075a      75a:	e8 01 00 00 00       	call   760 <.altinstr_replacement+0x760>
075f      75f:	cc                   	int3
0760      760:	48 83 c4 08          	add    $0x8,%rsp
0764      764:	0f ae e8             	lfence
0767      767:	e8 00 00 00 00       	call   76c <.altinstr_replacement+0x76c>	768: R_X86_64_PLT32	zen_untrain_ret-0x4
076c      76c:	e8 00 00 00 00       	call   771 <.altinstr_replacement+0x771>	76d: R_X86_64_PLT32	entry_ibpb-0x4
0771      771:	48 c7 c0 10 00 00 00 	mov    $0x10,%rax
0778      778:	e8 01 00 00 00       	call   77e <.altinstr_replacement+0x77e>
077d      77d:	cc                   	int3
077e      77e:	e8 01 00 00 00       	call   784 <.altinstr_replacement+0x784>
0783      783:	cc                   	int3
0784      784:	48 83 c4 10          	add    $0x10,%rsp
0788      788:	48 ff c8             	dec    %rax
078b      78b:	75 eb                	jne    778 <.altinstr_replacement+0x778>
078d      78d:	0f ae e8             	lfence
0790      790:	e8 01 00 00 00       	call   796 <.altinstr_replacement+0x796>
0795      795:	cc                   	int3
0796      796:	48 83 c4 08          	add    $0x8,%rsp
079a      79a:	0f ae e8             	lfence
079d      79d:	e8 00 00 00 00       	call   7a2 <.altinstr_replacement+0x7a2>	79e: R_X86_64_PLT32	zen_untrain_ret-0x4
07a2      7a2:	e8 00 00 00 00       	call   7a7 <.altinstr_replacement+0x7a7>	7a3: R_X86_64_PLT32	entry_ibpb-0x4
07a7      7a7:	48 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbp
07b1      7b1:	0f 01 cb             	stac
07b4      7b4:	e8 00 00 00 00       	call   7b9 <.altinstr_replacement+0x7b9>	7b5: R_X86_64_PLT32	clear_user_erms-0x4
07b9      7b9:	e8 00 00 00 00       	call   7be <.altinstr_replacement+0x7be>	7ba: R_X86_64_PLT32	clear_user_rep_good-0x4
07be      7be:	e8 00 00 00 00       	call   7c3 <.altinstr_replacement+0x7c3>	7bf: R_X86_64_PLT32	clear_user_original-0x4
07c3      7c3:	0f 01 ca             	clac
07c6      7c6:	e9 00 00 00 00       	jmp    7cb <.altinstr_replacement+0x7cb>	7c7: R_X86_64_PC32	.text+0x2191a5
07cb      7cb:	e8 00 00 00 00       	call   7d0 <.altinstr_replacement+0x7d0>	7cc: R_X86_64_PLT32	clear_page_rep-0x4
07d0      7d0:	e8 00 00 00 00       	call   7d5 <.altinstr_replacement+0x7d5>	7d1: R_X86_64_PLT32	clear_page_erms-0x4
07d5      7d5:	48 89 f8             	mov    %rdi,%rax
07d8      7d8:	e9 00 00 00 00       	jmp    7dd <.altinstr_replacement+0x7dd>	7d9: R_X86_64_PC32	.init.text+0x250ed
07dd      7dd:	e9 00 00 00 00       	jmp    7e2 <.altinstr_replacement+0x7e2>	7de: R_X86_64_PC32	.init.text+0x2655c
07e2      7e2:	9c                   	pushf
07e3      7e3:	58                   	pop    %rax
07e4      7e4:	48 89 f8             	mov    %rdi,%rax
07e7      7e7:	48 89 f8             	mov    %rdi,%rax
07ea      7ea:	48 89 f8             	mov    %rdi,%rax
07ed      7ed:	48 89 f8             	mov    %rdi,%rax
07f0      7f0:	48 89 f8             	mov    %rdi,%rax
07f3      7f3:	48 89 f8             	mov    %rdi,%rax
07f6      7f6:	48 89 f8             	mov    %rdi,%rax
07f9      7f9:	48 89 f8             	mov    %rdi,%rax
07fc      7fc:	48 89 f8             	mov    %rdi,%rax
07ff      7ff:	48 89 f8             	mov    %rdi,%rax
0802      802:	48 89 f8             	mov    %rdi,%rax
0805      805:	9c                   	pushf
0806      806:	58                   	pop    %rax
0807      807:	fa                   	cli
0808      808:	9c                   	pushf
0809      809:	58                   	pop    %rax
080a      80a:	fb                   	sti
080b      80b:	9c                   	pushf
080c      80c:	58                   	pop    %rax
080d      80d:	fa                   	cli
080e      80e:	0f 20 d8             	mov    %cr3,%rax
0811      811:	48 89 f8             	mov    %rdi,%rax
0814      814:	48 89 f8             	mov    %rdi,%rax
0817      817:	48 89 f8             	mov    %rdi,%rax
081a      81a:	48 89 f8             	mov    %rdi,%rax
081d      81d:	48 89 f8             	mov    %rdi,%rax
0820      820:	48 89 f8             	mov    %rdi,%rax
0823      823:	48 89 f8             	mov    %rdi,%rax
0826      826:	48 be 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rsi
0830      830:	e9 00 00 00 00       	jmp    835 <.altinstr_replacement+0x835>	831: R_X86_64_PC32	.init.text+0x29be5
0835      835:	48 89 f8             	mov    %rdi,%rax
0838      838:	e9 00 00 00 00       	jmp    83d <.altinstr_replacement+0x83d>	839: R_X86_64_PC32	.text+0x229ff0
083d      83d:	48 89 f8             	mov    %rdi,%rax
0840      840:	48 89 f8             	mov    %rdi,%rax
0843      843:	48 89 f8             	mov    %rdi,%rax
0846      846:	e9 00 00 00 00       	jmp    84b <.altinstr_replacement+0x84b>	847: R_X86_64_PC32	.text+0x22bcb2
084b      84b:	e9 00 00 00 00       	jmp    850 <.altinstr_replacement+0x850>	84c: R_X86_64_PC32	.text+0x22bd25
0850      850:	48 89 f8             	mov    %rdi,%rax
0853      853:	48 89 f8             	mov    %rdi,%rax
0856      856:	9c                   	pushf
0857      857:	58                   	pop    %rax
0858      858:	fb                   	sti
0859      859:	9c                   	pushf
085a      85a:	58                   	pop    %rax
085b      85b:	fa                   	cli
085c      85c:	48 be 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rsi
0866      866:	48 be 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rsi
0870      870:	9c                   	pushf
0871      871:	58                   	pop    %rax
0872      872:	9c                   	pushf
0873      873:	58                   	pop    %rax
0874      874:	48 89 f8             	mov    %rdi,%rax
0877      877:	e8 00 00 00 00       	call   87c <.altinstr_replacement+0x87c>	878: R_X86_64_PLT32	clear_page_rep-0x4
087c      87c:	e8 00 00 00 00       	call   881 <.altinstr_replacement+0x881>	87d: R_X86_64_PLT32	clear_page_erms-0x4
0881      881:	e8 00 00 00 00       	call   886 <.altinstr_replacement+0x886>	882: R_X86_64_PLT32	clear_page_rep-0x4
0886      886:	e8 00 00 00 00       	call   88b <.altinstr_replacement+0x88b>	887: R_X86_64_PLT32	clear_page_erms-0x4
088b      88b:	e8 00 00 00 00       	call   890 <.altinstr_replacement+0x890>	88c: R_X86_64_PLT32	clear_page_rep-0x4
0890      890:	e8 00 00 00 00       	call   895 <.altinstr_replacement+0x895>	891: R_X86_64_PLT32	clear_page_erms-0x4
0895      895:	e9 00 00 00 00       	jmp    89a <.altinstr_replacement+0x89a>	896: R_X86_64_PC32	.init.text+0x2b2a4
089a      89a:	e9 00 00 00 00       	jmp    89f <.altinstr_replacement+0x89f>	89b: R_X86_64_PC32	.init.text+0x2b465
089f      89f:	48 89 f8             	mov    %rdi,%rax
08a2      8a2:	48 89 f8             	mov    %rdi,%rax
08a5      8a5:	48 89 f8             	mov    %rdi,%rax
08a8      8a8:	e8 00 00 00 00       	call   8ad <.altinstr_replacement+0x8ad>	8a9: R_X86_64_PLT32	clear_page_rep-0x4
08ad      8ad:	e8 00 00 00 00       	call   8b2 <.altinstr_replacement+0x8b2>	8ae: R_X86_64_PLT32	clear_page_erms-0x4
08b2      8b2:	e8 00 00 00 00       	call   8b7 <.altinstr_replacement+0x8b7>	8b3: R_X86_64_PLT32	clear_page_rep-0x4
08b7      8b7:	e8 00 00 00 00       	call   8bc <.altinstr_replacement+0x8bc>	8b8: R_X86_64_PLT32	clear_page_erms-0x4
08bc      8bc:	9c                   	pushf
08bd      8bd:	58                   	pop    %rax
08be      8be:	9c                   	pushf
08bf      8bf:	58                   	pop    %rax
08c0      8c0:	fa                   	cli
08c1      8c1:	e8 00 00 00 00       	call   8c6 <.altinstr_replacement+0x8c6>	8c2: R_X86_64_PLT32	__x86_indirect_thunk_rax-0x4
08c6      8c6:	0f ae e8             	lfence
08c9      8c9:	ff d0                	call   *%rax
08cb      8cb:	9c                   	pushf
08cc      8cc:	58                   	pop    %rax
08cd      8cd:	fb                   	sti
08ce      8ce:	9c                   	pushf
08cf      8cf:	58                   	pop    %rax
08d0      8d0:	9c                   	pushf
08d1      8d1:	58                   	pop    %rax
08d2      8d2:	9c                   	pushf
08d3      8d3:	58                   	pop    %rax
08d4      8d4:	48 89 f8             	mov    %rdi,%rax
08d7      8d7:	48 89 f8             	mov    %rdi,%rax
08da      8da:	48 89 f8             	mov    %rdi,%rax
08dd      8dd:	48 89 f8             	mov    %rdi,%rax
08e0      8e0:	48 89 f8             	mov    %rdi,%rax
08e3      8e3:	48 89 f8             	mov    %rdi,%rax
08e6      8e6:	48 89 f8             	mov    %rdi,%rax
08e9      8e9:	fb                   	sti
08ea      8ea:	0f 22 df             	mov    %rdi,%cr3
08ed      8ed:	9c                   	pushf
08ee      8ee:	58                   	pop    %rax
08ef      8ef:	fa                   	cli
08f0      8f0:	fb                   	sti
08f1      8f1:	0f 22 df             	mov    %rdi,%cr3
08f4      8f4:	9c                   	pushf
08f5      8f5:	58                   	pop    %rax
08f6      8f6:	fa                   	cli
08f7      8f7:	e8 00 00 00 00       	call   8fc <.altinstr_replacement+0x8fc>	8f8: R_X86_64_PLT32	__x86_indirect_thunk_r15-0x4
08fc      8fc:	0f ae e8             	lfence
08ff      8ff:	41 ff d7             	call   *%r15
0902      902:	9c                   	pushf
0903      903:	58                   	pop    %rax
0904      904:	fb                   	sti
0905      905:	e9 00 00 00 00       	jmp    90a <.altinstr_replacement+0x90a>	906: R_X86_64_PC32	.init.text+0x305f1
090a      90a:	e8 00 00 00 00       	call   90f <.altinstr_replacement+0x90f>	90b: R_X86_64_PLT32	__x86_indirect_thunk_r15-0x4
090f      90f:	0f ae e8             	lfence
0912      912:	41 ff d7             	call   *%r15
0915      915:	e8 00 00 00 00       	call   91a <.altinstr_replacement+0x91a>	916: R_X86_64_PLT32	__x86_indirect_thunk_r12-0x4
091a      91a:	0f ae e8             	lfence
091d      91d:	41 ff d4             	call   *%r12
0920      920:	9c                   	pushf
0921      921:	58                   	pop    %rax
0922      922:	fa                   	cli
0923      923:	e8 00 00 00 00       	call   928 <.altinstr_replacement+0x928>	924: R_X86_64_PLT32	__x86_indirect_thunk_rbp-0x4
0928      928:	0f ae e8             	lfence
092b      92b:	ff d5                	call   *%rbp
092d      92d:	e8 00 00 00 00       	call   932 <.altinstr_replacement+0x932>	92e: R_X86_64_PLT32	__x86_indirect_thunk_rbx-0x4
0932      932:	0f ae e8             	lfence
0935      935:	ff d3                	call   *%rbx
0937      937:	9c                   	pushf
0938      938:	58                   	pop    %rax
0939      939:	fb                   	sti
093a      93a:	9c                   	pushf
093b      93b:	58                   	pop    %rax
093c      93c:	9c                   	pushf
093d      93d:	58                   	pop    %rax
093e      93e:	fb                   	sti
093f      93f:	9c                   	pushf
0940      940:	58                   	pop    %rax
0941      941:	fb                   	sti
0942      942:	9c                   	pushf
0943      943:	58                   	pop    %rax
0944      944:	fa                   	cli
0945      945:	9c                   	pushf
0946      946:	58                   	pop    %rax
0947      947:	e8 00 00 00 00       	call   94c <.altinstr_replacement+0x94c>	948: R_X86_64_PLT32	__x86_indirect_thunk_r12-0x4
094c      94c:	0f ae e8             	lfence
094f      94f:	41 ff d4             	call   *%r12
0952      952:	9c                   	pushf
0953      953:	58                   	pop    %rax
0954      954:	fb                   	sti
0955      955:	fb                   	sti
0956      956:	9c                   	pushf
0957      957:	58                   	pop    %rax
0958      958:	9c                   	pushf
0959      959:	58                   	pop    %rax
095a      95a:	fa                   	cli
095b      95b:	e8 00 00 00 00       	call   960 <.altinstr_replacement+0x960>	95c: R_X86_64_PLT32	__x86_indirect_thunk_r13-0x4
0960      960:	0f ae e8             	lfence
0963      963:	41 ff d5             	call   *%r13
0966      966:	9c                   	pushf
0967      967:	58                   	pop    %rax
0968      968:	fb                   	sti
0969      969:	9c                   	pushf
096a      96a:	58                   	pop    %rax
096b      96b:	fb                   	sti
096c      96c:	9c                   	pushf
096d      96d:	58                   	pop    %rax
096e      96e:	fa                   	cli
096f      96f:	e8 00 00 00 00       	call   974 <.altinstr_replacement+0x974>	970: R_X86_64_PLT32	__x86_indirect_thunk_r12-0x4
0974      974:	0f ae e8             	lfence
0977      977:	41 ff d4             	call   *%r12
097a      97a:	9c                   	pushf
097b      97b:	58                   	pop    %rax
097c      97c:	fb                   	sti
097d      97d:	9c                   	pushf
097e      97e:	58                   	pop    %rax
097f      97f:	fa                   	cli
0980      980:	9c                   	pushf
0981      981:	58                   	pop    %rax
0982      982:	fb                   	sti
0983      983:	e8 00 00 00 00       	call   988 <.altinstr_replacement+0x988>	984: R_X86_64_PLT32	__x86_indirect_thunk_r12-0x4
0988      988:	0f ae e8             	lfence
098b      98b:	41 ff d4             	call   *%r12
098e      98e:	9c                   	pushf
098f      98f:	58                   	pop    %rax
0990      990:	fb                   	sti
0991      991:	9c                   	pushf
0992      992:	58                   	pop    %rax
0993      993:	fa                   	cli
0994      994:	9c                   	pushf
0995      995:	58                   	pop    %rax
0996      996:	fb                   	sti
0997      997:	9c                   	pushf
0998      998:	58                   	pop    %rax
0999      999:	9c                   	pushf
099a      99a:	58                   	pop    %rax
099b      99b:	fa                   	cli
099c      99c:	9c                   	pushf
099d      99d:	58                   	pop    %rax
099e      99e:	fb                   	sti
099f      99f:	9c                   	pushf
09a0      9a0:	58                   	pop    %rax
09a1      9a1:	9c                   	pushf
09a2      9a2:	58                   	pop    %rax
09a3      9a3:	fa                   	cli
09a4      9a4:	9c                   	pushf
09a5      9a5:	58                   	pop    %rax
09a6      9a6:	fb                   	sti
09a7      9a7:	9c                   	pushf
09a8      9a8:	58                   	pop    %rax
09a9      9a9:	fb                   	sti
09aa      9aa:	e9 00 00 00 00       	jmp    9af <.altinstr_replacement+0x9af>	9ab: R_X86_64_PC32	.text+0x24a211
09af      9af:	9c                   	pushf
09b0      9b0:	58                   	pop    %rax
09b1      9b1:	fa                   	cli
09b2      9b2:	e8 00 00 00 00       	call   9b7 <.altinstr_replacement+0x9b7>	9b3: R_X86_64_PLT32	__x86_indirect_thunk_r14-0x4
09b7      9b7:	0f ae e8             	lfence
09ba      9ba:	41 ff d6             	call   *%r14
09bd      9bd:	9c                   	pushf
09be      9be:	58                   	pop    %rax
09bf      9bf:	fb                   	sti
09c0      9c0:	9c                   	pushf
09c1      9c1:	58                   	pop    %rax
09c2      9c2:	fb                   	sti
09c3      9c3:	9c                   	pushf
09c4      9c4:	58                   	pop    %rax
09c5      9c5:	fa                   	cli
09c6      9c6:	9c                   	pushf
09c7      9c7:	58                   	pop    %rax
09c8      9c8:	e8 00 00 00 00       	call   9cd <.altinstr_replacement+0x9cd>	9c9: R_X86_64_PLT32	__x86_indirect_thunk_r13-0x4
09cd      9cd:	0f ae e8             	lfence
09d0      9d0:	41 ff d5             	call   *%r13
09d3      9d3:	9c                   	pushf
09d4      9d4:	58                   	pop    %rax
09d5      9d5:	fb                   	sti
09d6      9d6:	e8 00 00 00 00       	call   9db <.altinstr_replacement+0x9db>	9d7: R_X86_64_PLT32	__x86_indirect_thunk_rax-0x4
09db      9db:	0f ae e8             	lfence
09de      9de:	ff d0                	call   *%rax
09e0      9e0:	41 87 b4 24 00 c0 5f ff 	xchg   %esi,-0xa04000(%r12)
09e8      9e8:	e8 00 00 00 00       	call   9ed <.altinstr_replacement+0x9ed>	9e9: R_X86_64_PLT32	__x86_indirect_thunk_rbx-0x4
09ed      9ed:	0f ae e8             	lfence
09f0      9f0:	ff d3                	call   *%rbx
09f2      9f2:	9c                   	pushf
09f3      9f3:	58                   	pop    %rax
09f4      9f4:	fa                   	cli
09f5      9f5:	e8 00 00 00 00       	call   9fa <.altinstr_replacement+0x9fa>	9f6: R_X86_64_PLT32	__x86_indirect_thunk_r14-0x4
09fa      9fa:	0f ae e8             	lfence
09fd      9fd:	41 ff d6             	call   *%r14
0a00      a00:	9c                   	pushf
0a01      a01:	58                   	pop    %rax
0a02      a02:	fb                   	sti
0a03      a03:	9c                   	pushf
0a04      a04:	58                   	pop    %rax
0a05      a05:	fa                   	cli
0a06      a06:	e8 00 00 00 00       	call   a0b <.altinstr_replacement+0xa0b>	a07: R_X86_64_PLT32	__x86_indirect_thunk_r13-0x4
0a0b      a0b:	0f ae e8             	lfence
0a0e      a0e:	41 ff d5             	call   *%r13
0a11      a11:	9c                   	pushf
0a12      a12:	58                   	pop    %rax
0a13      a13:	fb                   	sti
0a14      a14:	9c                   	pushf
0a15      a15:	58                   	pop    %rax
0a16      a16:	fa                   	cli
0a17      a17:	e8 00 00 00 00       	call   a1c <.altinstr_replacement+0xa1c>	a18: R_X86_64_PLT32	__x86_indirect_thunk_rbp-0x4
0a1c      a1c:	0f ae e8             	lfence
0a1f      a1f:	ff d5                	call   *%rbp
0a21      a21:	9c                   	pushf
0a22      a22:	58                   	pop    %rax
0a23      a23:	fb                   	sti
0a24      a24:	9c                   	pushf
0a25      a25:	58                   	pop    %rax
0a26      a26:	fa                   	cli
0a27      a27:	9c                   	pushf
0a28      a28:	58                   	pop    %rax
0a29      a29:	fb                   	sti
0a2a      a2a:	9c                   	pushf
0a2b      a2b:	58                   	pop    %rax
0a2c      a2c:	fa                   	cli
0a2d      a2d:	9c                   	pushf
0a2e      a2e:	58                   	pop    %rax
0a2f      a2f:	fb                   	sti
0a30      a30:	0f 22 df             	mov    %rdi,%cr3
0a33      a33:	e9 00 00 00 00       	jmp    a38 <.altinstr_replacement+0xa38>	a34: R_X86_64_PC32	.noinstr.text+0x25a9
0a38      a38:	9c                   	pushf
0a39      a39:	58                   	pop    %rax
0a3a      a3a:	fa                   	cli
0a3b      a3b:	e9 00 00 00 00       	jmp    a40 <.altinstr_replacement+0xa40>	a3c: R_X86_64_PC32	.text+0x24dc79
0a40      a40:	9c                   	pushf
0a41      a41:	58                   	pop    %rax
0a42      a42:	fb                   	sti
0a43      a43:	e9 00 00 00 00       	jmp    a48 <.altinstr_replacement+0xa48>	a44: R_X86_64_PC32	.noinstr.text+0x2626
0a48      a48:	e9 00 00 00 00       	jmp    a4d <.altinstr_replacement+0xa4d>	a49: R_X86_64_PC32	.text+0x24e236
0a4d      a4d:	0f 20 d0             	mov    %cr2,%rax
0a50      a50:	0f 20 d8             	mov    %cr3,%rax
0a53      a53:	e9 00 00 00 00       	jmp    a58 <.altinstr_replacement+0xa58>	a54: R_X86_64_PC32	.text.unlikely+0x20aa6
0a58      a58:	e9 00 00 00 00       	jmp    a5d <.altinstr_replacement+0xa5d>	a59: R_X86_64_PC32	.text.unlikely+0x20da7
0a5d      a5d:	9c                   	pushf
0a5e      a5e:	58                   	pop    %rax
0a5f      a5f:	fa                   	cli
0a60      a60:	9c                   	pushf
0a61      a61:	58                   	pop    %rax
0a62      a62:	fb                   	sti
0a63      a63:	9c                   	pushf
0a64      a64:	58                   	pop    %rax
0a65      a65:	fa                   	cli
0a66      a66:	9c                   	pushf
0a67      a67:	58                   	pop    %rax
0a68      a68:	fb                   	sti
0a69      a69:	e9 00 00 00 00       	jmp    a6e <.altinstr_replacement+0xa6e>	a6a: R_X86_64_PC32	.text+0x24efde
0a6e      a6e:	e9 00 00 00 00       	jmp    a73 <.altinstr_replacement+0xa73>	a6f: R_X86_64_PC32	.text+0x24f036
0a73      a73:	e9 00 00 00 00       	jmp    a78 <.altinstr_replacement+0xa78>	a74: R_X86_64_PC32	.text+0x24ee05
0a78      a78:	e9 00 00 00 00       	jmp    a7d <.altinstr_replacement+0xa7d>	a79: R_X86_64_PC32	.text+0x24ee8a
0a7d      a7d:	e9 00 00 00 00       	jmp    a82 <.altinstr_replacement+0xa82>	a7e: R_X86_64_PC32	.text+0x24eed0
0a82      a82:	e9 00 00 00 00       	jmp    a87 <.altinstr_replacement+0xa87>	a83: R_X86_64_PC32	.text+0x24f2a6
0a87      a87:	e9 00 00 00 00       	jmp    a8c <.altinstr_replacement+0xa8c>	a88: R_X86_64_PC32	.text+0x24f280
0a8c      a8c:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
0a96      a96:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
0aa0      aa0:	48 ba 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rdx
0aaa      aaa:	0f 01 cb             	stac
0aad      aad:	0f ae e8             	lfence
0ab0      ab0:	0f 01 ca             	clac
0ab3      ab3:	0f 01 ca             	clac
0ab6      ab6:	48 ba 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rdx
0ac0      ac0:	0f 01 cb             	stac
0ac3      ac3:	0f ae e8             	lfence
0ac6      ac6:	0f 01 ca             	clac
0ac9      ac9:	0f 01 ca             	clac
0acc      acc:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
0ad6      ad6:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
0ae0      ae0:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
0aea      aea:	fb                   	sti
0aeb      aeb:	fa                   	cli
0aec      aec:	9c                   	pushf
0aed      aed:	58                   	pop    %rax
0aee      aee:	e9 00 00 00 00       	jmp    af3 <.altinstr_replacement+0xaf3>	aef: R_X86_64_PC32	.text+0x25217e
0af3      af3:	e9 00 00 00 00       	jmp    af8 <.altinstr_replacement+0xaf8>	af4: R_X86_64_PC32	.text+0x2521c3
0af8      af8:	9c                   	pushf
0af9      af9:	58                   	pop    %rax
0afa      afa:	fa                   	cli
0afb      afb:	fb                   	sti
0afc      afc:	e9 00 00 00 00       	jmp    b01 <.altinstr_replacement+0xb01>	afd: R_X86_64_PC32	.text+0x2527ae
0b01      b01:	fb                   	sti
0b02      b02:	9c                   	pushf
0b03      b03:	58                   	pop    %rax
0b04      b04:	fa                   	cli
0b05      b05:	e9 00 00 00 00       	jmp    b0a <.altinstr_replacement+0xb0a>	b06: R_X86_64_PC32	.text+0x252876
0b0a      b0a:	fb                   	sti
0b0b      b0b:	fb                   	sti
0b0c      b0c:	fb                   	sti
0b0d      b0d:	48 ba 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rdx
0b17      b17:	e9 00 00 00 00       	jmp    b1c <.altinstr_replacement+0xb1c>	b18: R_X86_64_PC32	.noinstr.text+0x2a40
0b1c      b1c:	fb                   	sti
0b1d      b1d:	9c                   	pushf
0b1e      b1e:	58                   	pop    %rax
0b1f      b1f:	fa                   	cli
0b20      b20:	0f 20 d0             	mov    %cr2,%rax
0b23      b23:	e9 00 00 00 00       	jmp    b28 <.altinstr_replacement+0xb28>	b24: R_X86_64_PC32	.noinstr.text+0x3250
0b28      b28:	e9 00 00 00 00       	jmp    b2d <.altinstr_replacement+0xb2d>	b29: R_X86_64_PC32	.noinstr.text+0x3504
0b2d      b2d:	fb                   	sti
0b2e      b2e:	9c                   	pushf
0b2f      b2f:	58                   	pop    %rax
0b30      b30:	fa                   	cli
0b31      b31:	e9 00 00 00 00       	jmp    b36 <.altinstr_replacement+0xb36>	b32: R_X86_64_PC32	.init.text+0x3236b
0b36      b36:	9c                   	pushf
0b37      b37:	58                   	pop    %rax
0b38      b38:	fb                   	sti
0b39      b39:	c6 07 00             	movb   $0x0,(%rdi)
0b3c      b3c:	9c                   	pushf
0b3d      b3d:	58                   	pop    %rax
0b3e      b3e:	fa                   	cli
0b3f      b3f:	0f 20 d0             	mov    %cr2,%rax
0b42      b42:	e9 00 00 00 00       	jmp    b47 <.altinstr_replacement+0xb47>	b43: R_X86_64_PC32	.noinstr.text+0x4384
0b47      b47:	0f 20 d0             	mov    %cr2,%rax
0b4a      b4a:	e9 00 00 00 00       	jmp    b4f <.altinstr_replacement+0xb4f>	b4b: R_X86_64_PC32	.text+0x25cc6c
0b4f      b4f:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
0b59      b59:	0f 01 cb             	stac
0b5c      b5c:	e8 00 00 00 00       	call   b61 <.altinstr_replacement+0xb61>	b5d: R_X86_64_PLT32	clear_user_erms-0x4
0b61      b61:	e8 00 00 00 00       	call   b66 <.altinstr_replacement+0xb66>	b62: R_X86_64_PLT32	clear_user_rep_good-0x4
0b66      b66:	e8 00 00 00 00       	call   b6b <.altinstr_replacement+0xb6b>	b67: R_X86_64_PLT32	clear_user_original-0x4
0b6b      b6b:	0f 01 ca             	clac
0b6e      b6e:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
0b78      b78:	0f 01 cb             	stac
0b7b      b7b:	e8 00 00 00 00       	call   b80 <.altinstr_replacement+0xb80>	b7c: R_X86_64_PLT32	clear_user_erms-0x4
0b80      b80:	e8 00 00 00 00       	call   b85 <.altinstr_replacement+0xb85>	b81: R_X86_64_PLT32	clear_user_rep_good-0x4
0b85      b85:	e8 00 00 00 00       	call   b8a <.altinstr_replacement+0xb8a>	b86: R_X86_64_PLT32	clear_user_original-0x4
0b8a      b8a:	0f 01 ca             	clac
0b8d      b8d:	48 89 f8             	mov    %rdi,%rax
0b90      b90:	e9 00 00 00 00       	jmp    b95 <.altinstr_replacement+0xb95>	b91: R_X86_64_PC32	.text+0x25dfa4
0b95      b95:	9c                   	pushf
0b96      b96:	58                   	pop    %rax
0b97      b97:	e9 00 00 00 00       	jmp    b9c <.altinstr_replacement+0xb9c>	b98: R_X86_64_PC32	.init.text+0x33301
0b9c      b9c:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
0ba6      ba6:	0f 01 cb             	stac
0ba9      ba9:	0f ae e8             	lfence
0bac      bac:	0f 01 ca             	clac
0baf      baf:	0f 01 ca             	clac
0bb2      bb2:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
0bbc      bbc:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
0bc6      bc6:	e9 00 00 00 00       	jmp    bcb <.altinstr_replacement+0xbcb>	bc7: R_X86_64_PC32	.text.unlikely+0x21db5
0bcb      bcb:	48 89 f8             	mov    %rdi,%rax
0bce      bce:	48 89 f8             	mov    %rdi,%rax
0bd1      bd1:	48 89 f8             	mov    %rdi,%rax
0bd4      bd4:	48 89 f8             	mov    %rdi,%rax
0bd7      bd7:	48 89 f8             	mov    %rdi,%rax
0bda      bda:	48 89 f8             	mov    %rdi,%rax
0bdd      bdd:	e9 00 00 00 00       	jmp    be2 <.altinstr_replacement+0xbe2>	bde: R_X86_64_PC32	.init.text+0x355da
0be2      be2:	48 89 f8             	mov    %rdi,%rax
0be5      be5:	e9 00 00 00 00       	jmp    bea <.altinstr_replacement+0xbea>	be6: R_X86_64_PC32	.init.text+0x35723
0bea      bea:	e9 00 00 00 00       	jmp    bef <.altinstr_replacement+0xbef>	beb: R_X86_64_PC32	.init.text+0x36b80
0bef      bef:	e9 00 00 00 00       	jmp    bf4 <.altinstr_replacement+0xbf4>	bf0: R_X86_64_PC32	.init.text+0x38c4f
0bf4      bf4:	e9 00 00 00 00       	jmp    bf9 <.altinstr_replacement+0xbf9>	bf5: R_X86_64_PC32	.text+0x2648ee
0bf9      bf9:	e9 00 00 00 00       	jmp    bfe <.altinstr_replacement+0xbfe>	bfa: R_X86_64_PC32	.text+0x264ae5
0bfe      bfe:	e9 00 00 00 00       	jmp    c03 <.altinstr_replacement+0xc03>	bff: R_X86_64_PC32	.text+0x264965
0c03      c03:	48 89 f8             	mov    %rdi,%rax
0c06      c06:	9c                   	pushf
0c07      c07:	58                   	pop    %rax
0c08      c08:	fa                   	cli
0c09      c09:	9c                   	pushf
0c0a      c0a:	58                   	pop    %rax
0c0b      c0b:	fb                   	sti
0c0c      c0c:	e9 00 00 00 00       	jmp    c11 <.altinstr_replacement+0xc11>	c0d: R_X86_64_PC32	.text+0x265394
0c11      c11:	9c                   	pushf
0c12      c12:	58                   	pop    %rax
0c13      c13:	fa                   	cli
0c14      c14:	9c                   	pushf
0c15      c15:	58                   	pop    %rax
0c16      c16:	fb                   	sti
0c17      c17:	9c                   	pushf
0c18      c18:	58                   	pop    %rax
0c19      c19:	fa                   	cli
0c1a      c1a:	9c                   	pushf
0c1b      c1b:	58                   	pop    %rax
0c1c      c1c:	fb                   	sti
0c1d      c1d:	e9 00 00 00 00       	jmp    c22 <.altinstr_replacement+0xc22>	c1e: R_X86_64_PC32	.text+0x265df5
0c22      c22:	e9 00 00 00 00       	jmp    c27 <.altinstr_replacement+0xc27>	c23: R_X86_64_PC32	.text+0x2665b2
0c27      c27:	48 ba 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rdx
0c31      c31:	48 ba 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rdx
0c3b      c3b:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
0c45      c45:	0f ae e8             	lfence
0c48      c48:	0f 31                	rdtsc
0c4a      c4a:	0f 01 f9             	rdtscp
0c4d      c4d:	9c                   	pushf
0c4e      c4e:	58                   	pop    %rax
0c4f      c4f:	fa                   	cli
0c50      c50:	9c                   	pushf
0c51      c51:	58                   	pop    %rax
0c52      c52:	fb                   	sti
0c53      c53:	9c                   	pushf
0c54      c54:	58                   	pop    %rax
0c55      c55:	fa                   	cli
0c56      c56:	9c                   	pushf
0c57      c57:	58                   	pop    %rax
0c58      c58:	fb                   	sti
0c59      c59:	9c                   	pushf
0c5a      c5a:	58                   	pop    %rax
0c5b      c5b:	fa                   	cli
0c5c      c5c:	9c                   	pushf
0c5d      c5d:	58                   	pop    %rax
0c5e      c5e:	fb                   	sti
0c5f      c5f:	9c                   	pushf
0c60      c60:	58                   	pop    %rax
0c61      c61:	fa                   	cli
0c62      c62:	9c                   	pushf
0c63      c63:	58                   	pop    %rax
0c64      c64:	fb                   	sti
0c65      c65:	e9 00 00 00 00       	jmp    c6a <.altinstr_replacement+0xc6a>	c66: R_X86_64_PC32	.ref.text+0x14bb
0c6a      c6a:	9c                   	pushf
0c6b      c6b:	58                   	pop    %rax
0c6c      c6c:	fa                   	cli
0c6d      c6d:	9c                   	pushf
0c6e      c6e:	58                   	pop    %rax
0c6f      c6f:	fb                   	sti
0c70      c70:	9c                   	pushf
0c71      c71:	58                   	pop    %rax
0c72      c72:	fa                   	cli
0c73      c73:	9c                   	pushf
0c74      c74:	58                   	pop    %rax
0c75      c75:	fb                   	sti
0c76      c76:	9c                   	pushf
0c77      c77:	58                   	pop    %rax
0c78      c78:	fb                   	sti
0c79      c79:	fa                   	cli
0c7a      c7a:	fb                   	sti
0c7b      c7b:	e9 00 00 00 00       	jmp    c80 <.altinstr_replacement+0xc80>	c7c: R_X86_64_PC32	.text+0x26c234
0c80      c80:	e9 00 00 00 00       	jmp    c85 <.altinstr_replacement+0xc85>	c81: R_X86_64_PC32	.text+0x26c50d
0c85      c85:	9c                   	pushf
0c86      c86:	58                   	pop    %rax
0c87      c87:	fa                   	cli
0c88      c88:	e9 00 00 00 00       	jmp    c8d <.altinstr_replacement+0xc8d>	c89: R_X86_64_PC32	.text+0x26cc73
0c8d      c8d:	9c                   	pushf
0c8e      c8e:	58                   	pop    %rax
0c8f      c8f:	fb                   	sti
0c90      c90:	e9 00 00 00 00       	jmp    c95 <.altinstr_replacement+0xc95>	c91: R_X86_64_PC32	.text+0x26cd22
0c95      c95:	e9 00 00 00 00       	jmp    c9a <.altinstr_replacement+0xc9a>	c96: R_X86_64_PC32	.text+0x26cd3f
0c9a      c9a:	e9 00 00 00 00       	jmp    c9f <.altinstr_replacement+0xc9f>	c9b: R_X86_64_PC32	.text+0x26cd91
0c9f      c9f:	e9 00 00 00 00       	jmp    ca4 <.altinstr_replacement+0xca4>	ca0: R_X86_64_PC32	.text+0x26cce9
0ca4      ca4:	e9 00 00 00 00       	jmp    ca9 <.altinstr_replacement+0xca9>	ca5: R_X86_64_PC32	.text+0x26d2b8
0ca9      ca9:	e9 00 00 00 00       	jmp    cae <.altinstr_replacement+0xcae>	caa: R_X86_64_PC32	.text+0x26d4c9
0cae      cae:	e9 00 00 00 00       	jmp    cb3 <.altinstr_replacement+0xcb3>	caf: R_X86_64_PC32	.text+0x26d6d1
0cb3      cb3:	e9 00 00 00 00       	jmp    cb8 <.altinstr_replacement+0xcb8>	cb4: R_X86_64_PC32	.text+0x26d525
0cb8      cb8:	e9 00 00 00 00       	jmp    cbd <.altinstr_replacement+0xcbd>	cb9: R_X86_64_PC32	.text+0x26d27f
0cbd      cbd:	e9 00 00 00 00       	jmp    cc2 <.altinstr_replacement+0xcc2>	cbe: R_X86_64_PC32	.text+0x26d5c8
0cc2      cc2:	e9 00 00 00 00       	jmp    cc7 <.altinstr_replacement+0xcc7>	cc3: R_X86_64_PC32	.text+0x26d72b
0cc7      cc7:	e9 00 00 00 00       	jmp    ccc <.altinstr_replacement+0xccc>	cc8: R_X86_64_PC32	.text+0x26d7b7
0ccc      ccc:	e9 00 00 00 00       	jmp    cd1 <.altinstr_replacement+0xcd1>	ccd: R_X86_64_PC32	.text+0x26d808
0cd1      cd1:	e9 00 00 00 00       	jmp    cd6 <.altinstr_replacement+0xcd6>	cd2: R_X86_64_PC32	.text+0x26d812
0cd6      cd6:	9c                   	pushf
0cd7      cd7:	58                   	pop    %rax
0cd8      cd8:	fa                   	cli
0cd9      cd9:	e9 00 00 00 00       	jmp    cde <.altinstr_replacement+0xcde>	cda: R_X86_64_PC32	.text+0x26debd
0cde      cde:	9c                   	pushf
0cdf      cdf:	58                   	pop    %rax
0ce0      ce0:	fa                   	cli
0ce1      ce1:	fb                   	sti
0ce2      ce2:	9c                   	pushf
0ce3      ce3:	58                   	pop    %rax
0ce4      ce4:	fa                   	cli
0ce5      ce5:	9c                   	pushf
0ce6      ce6:	58                   	pop    %rax
0ce7      ce7:	fb                   	sti
0ce8      ce8:	48 0f ae 37          	xsaveopt64 (%rdi)
0cec      cec:	48 0f c7 27          	xsavec64 (%rdi)
0cf0      cf0:	48 0f c7 2f          	xsaves64 (%rdi)
0cf4      cf4:	e9 00 00 00 00       	jmp    cf9 <.altinstr_replacement+0xcf9>	cf5: R_X86_64_PC32	.text+0x26f0b7
0cf9      cf9:	e9 00 00 00 00       	jmp    cfe <.altinstr_replacement+0xcfe>	cfa: R_X86_64_PC32	.text+0x26f5a4
0cfe      cfe:	e9 00 00 00 00       	jmp    d03 <.altinstr_replacement+0xd03>	cff: R_X86_64_PC32	.text+0x26f6d1
0d03      d03:	e9 00 00 00 00       	jmp    d08 <.altinstr_replacement+0xd08>	d04: R_X86_64_PC32	.text+0x27014e
0d08      d08:	e9 00 00 00 00       	jmp    d0d <.altinstr_replacement+0xd0d>	d09: R_X86_64_PC32	.text+0x270439
0d0d      d0d:	e9 00 00 00 00       	jmp    d12 <.altinstr_replacement+0xd12>	d0e: R_X86_64_PC32	.text+0x270482
0d12      d12:	48 0f c7 1f          	xrstors64 (%rdi)
0d16      d16:	e9 00 00 00 00       	jmp    d1b <.altinstr_replacement+0xd1b>	d17: R_X86_64_PC32	.text+0x270f43
0d1b      d1b:	e9 00 00 00 00       	jmp    d20 <.altinstr_replacement+0xd20>	d1c: R_X86_64_PC32	.text+0x2712c6
0d20      d20:	e9 00 00 00 00       	jmp    d25 <.altinstr_replacement+0xd25>	d21: R_X86_64_PC32	.text+0x2713be
0d25      d25:	e9 00 00 00 00       	jmp    d2a <.altinstr_replacement+0xd2a>	d26: R_X86_64_PC32	.text+0x271fa1
0d2a      d2a:	e9 00 00 00 00       	jmp    d2f <.altinstr_replacement+0xd2f>	d2b: R_X86_64_PC32	.text+0x2727e6
0d2f      d2f:	48 0f c7 1f          	xrstors64 (%rdi)
0d33      d33:	e9 00 00 00 00       	jmp    d38 <.altinstr_replacement+0xd38>	d34: R_X86_64_PC32	.text+0x2727c2
0d38      d38:	48 0f c7 1f          	xrstors64 (%rdi)
0d3c      d3c:	e9 00 00 00 00       	jmp    d41 <.altinstr_replacement+0xd41>	d3d: R_X86_64_PC32	.text+0x2729f7
0d41      d41:	e8 00 00 00 00       	call   d46 <.altinstr_replacement+0xd46>	d42: R_X86_64_PLT32	copy_user_generic_string-0x4
0d46      d46:	e8 00 00 00 00       	call   d4b <.altinstr_replacement+0xd4b>	d47: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
0d4b      d4b:	e9 00 00 00 00       	jmp    d50 <.altinstr_replacement+0xd50>	d4c: R_X86_64_PC32	.text+0x2733f9
0d50      d50:	e9 00 00 00 00       	jmp    d55 <.altinstr_replacement+0xd55>	d51: R_X86_64_PC32	.text+0x2736c2
0d55      d55:	e9 00 00 00 00       	jmp    d5a <.altinstr_replacement+0xd5a>	d56: R_X86_64_PC32	.text+0x2737fc
0d5a      d5a:	e9 00 00 00 00       	jmp    d5f <.altinstr_replacement+0xd5f>	d5b: R_X86_64_PC32	.text+0x273917
0d5f      d5f:	e9 00 00 00 00       	jmp    d64 <.altinstr_replacement+0xd64>	d60: R_X86_64_PC32	.text+0x273d33
0d64      d64:	e9 00 00 00 00       	jmp    d69 <.altinstr_replacement+0xd69>	d65: R_X86_64_PC32	.text+0x273f4d
0d69      d69:	e8 00 00 00 00       	call   d6e <.altinstr_replacement+0xd6e>	d6a: R_X86_64_PLT32	copy_user_generic_string-0x4
0d6e      d6e:	e8 00 00 00 00       	call   d73 <.altinstr_replacement+0xd73>	d6f: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
0d73      d73:	48 0f ae 37          	xsaveopt64 (%rdi)
0d77      d77:	48 0f c7 27          	xsavec64 (%rdi)
0d7b      d7b:	48 0f c7 2f          	xsaves64 (%rdi)
0d7f      d7f:	e8 00 00 00 00       	call   d84 <.altinstr_replacement+0xd84>	d80: R_X86_64_PLT32	copy_user_generic_string-0x4
0d84      d84:	e8 00 00 00 00       	call   d89 <.altinstr_replacement+0xd89>	d85: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
0d89      d89:	e9 00 00 00 00       	jmp    d8e <.altinstr_replacement+0xd8e>	d8a: R_X86_64_PC32	.text+0x2742c9
0d8e      d8e:	e8 00 00 00 00       	call   d93 <.altinstr_replacement+0xd93>	d8f: R_X86_64_PLT32	copy_user_generic_string-0x4
0d93      d93:	e8 00 00 00 00       	call   d98 <.altinstr_replacement+0xd98>	d94: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
0d98      d98:	e9 00 00 00 00       	jmp    d9d <.altinstr_replacement+0xd9d>	d99: R_X86_64_PC32	.text+0x27475c
0d9d      d9d:	0f 01 cb             	stac
0da0      da0:	0f 01 ca             	clac
0da3      da3:	0f 01 cb             	stac
0da6      da6:	0f 01 ca             	clac
0da9      da9:	48 0f c7 1f          	xrstors64 (%rdi)
0dad      dad:	0f 01 cb             	stac
0db0      db0:	0f 01 ca             	clac
0db3      db3:	48 0f c7 1f          	xrstors64 (%rdi)
0db7      db7:	e9 00 00 00 00       	jmp    dbc <.altinstr_replacement+0xdbc>	db8: R_X86_64_PC32	.text+0x274bb5
0dbc      dbc:	e8 00 00 00 00       	call   dc1 <.altinstr_replacement+0xdc1>	dbd: R_X86_64_PLT32	copy_user_generic_string-0x4
0dc1      dc1:	e8 00 00 00 00       	call   dc6 <.altinstr_replacement+0xdc6>	dc2: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
0dc6      dc6:	e8 00 00 00 00       	call   dcb <.altinstr_replacement+0xdcb>	dc7: R_X86_64_PLT32	copy_user_generic_string-0x4
0dcb      dcb:	e8 00 00 00 00       	call   dd0 <.altinstr_replacement+0xdd0>	dcc: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
0dd0      dd0:	e9 00 00 00 00       	jmp    dd5 <.altinstr_replacement+0xdd5>	dd1: R_X86_64_PC32	.text+0x2750ac
0dd5      dd5:	e8 00 00 00 00       	call   dda <.altinstr_replacement+0xdda>	dd6: R_X86_64_PLT32	copy_user_generic_string-0x4
0dda      dda:	e8 00 00 00 00       	call   ddf <.altinstr_replacement+0xddf>	ddb: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
0ddf      ddf:	e9 00 00 00 00       	jmp    de4 <.altinstr_replacement+0xde4>	de0: R_X86_64_PC32	.text+0x27518d
0de4      de4:	e9 00 00 00 00       	jmp    de9 <.altinstr_replacement+0xde9>	de5: R_X86_64_PC32	.text+0x27532d
0de9      de9:	e9 00 00 00 00       	jmp    dee <.altinstr_replacement+0xdee>	dea: R_X86_64_PC32	.text+0x27543d
0dee      dee:	49 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r13
0df8      df8:	e9 00 00 00 00       	jmp    dfd <.altinstr_replacement+0xdfd>	df9: R_X86_64_PC32	.text+0x2755be
0dfd      dfd:	0f 01 cb             	stac
0e00      e00:	e8 00 00 00 00       	call   e05 <.altinstr_replacement+0xe05>	e01: R_X86_64_PLT32	clear_user_erms-0x4
0e05      e05:	e8 00 00 00 00       	call   e0a <.altinstr_replacement+0xe0a>	e06: R_X86_64_PLT32	clear_user_rep_good-0x4
0e0a      e0a:	e8 00 00 00 00       	call   e0f <.altinstr_replacement+0xe0f>	e0b: R_X86_64_PLT32	clear_user_original-0x4
0e0f      e0f:	0f 01 ca             	clac
0e12      e12:	e9 00 00 00 00       	jmp    e17 <.altinstr_replacement+0xe17>	e13: R_X86_64_PC32	.text+0x275872
0e17      e17:	0f 01 cb             	stac
0e1a      e1a:	0f 01 ca             	clac
0e1d      e1d:	0f 01 cb             	stac
0e20      e20:	e8 00 00 00 00       	call   e25 <.altinstr_replacement+0xe25>	e21: R_X86_64_PLT32	clear_user_erms-0x4
0e25      e25:	e8 00 00 00 00       	call   e2a <.altinstr_replacement+0xe2a>	e26: R_X86_64_PLT32	clear_user_rep_good-0x4
0e2a      e2a:	e8 00 00 00 00       	call   e2f <.altinstr_replacement+0xe2f>	e2b: R_X86_64_PLT32	clear_user_original-0x4
0e2f      e2f:	0f 01 ca             	clac
0e32      e32:	0f 01 cb             	stac
0e35      e35:	0f 01 ca             	clac
0e38      e38:	e9 00 00 00 00       	jmp    e3d <.altinstr_replacement+0xe3d>	e39: R_X86_64_PC32	.text+0x275be4
0e3d      e3d:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
0e47      e47:	e9 00 00 00 00       	jmp    e4c <.altinstr_replacement+0xe4c>	e48: R_X86_64_PC32	.text+0x275d93
0e4c      e4c:	e9 00 00 00 00       	jmp    e51 <.altinstr_replacement+0xe51>	e4d: R_X86_64_PC32	.init.text+0x3cf3a
0e51      e51:	e9 00 00 00 00       	jmp    e56 <.altinstr_replacement+0xe56>	e52: R_X86_64_PC32	.text+0x275e2b
0e56      e56:	e9 00 00 00 00       	jmp    e5b <.altinstr_replacement+0xe5b>	e57: R_X86_64_PC32	.text+0x275e5d
0e5b      e5b:	9c                   	pushf
0e5c      e5c:	58                   	pop    %rax
0e5d      e5d:	fa                   	cli
0e5e      e5e:	9c                   	pushf
0e5f      e5f:	58                   	pop    %rax
0e60      e60:	fb                   	sti
0e61      e61:	9c                   	pushf
0e62      e62:	58                   	pop    %rax
0e63      e63:	fa                   	cli
0e64      e64:	9c                   	pushf
0e65      e65:	58                   	pop    %rax
0e66      e66:	fb                   	sti
0e67      e67:	e9 00 00 00 00       	jmp    e6c <.altinstr_replacement+0xe6c>	e68: R_X86_64_PC32	.text+0x276983
0e6c      e6c:	e9 00 00 00 00       	jmp    e71 <.altinstr_replacement+0xe71>	e6d: R_X86_64_PC32	.text+0x276bb7
0e71      e71:	e9 00 00 00 00       	jmp    e76 <.altinstr_replacement+0xe76>	e72: R_X86_64_PC32	.text+0x277297
0e76      e76:	e9 00 00 00 00       	jmp    e7b <.altinstr_replacement+0xe7b>	e77: R_X86_64_PC32	.text+0x277600
0e7b      e7b:	e9 00 00 00 00       	jmp    e80 <.altinstr_replacement+0xe80>	e7c: R_X86_64_PC32	.text+0x2775af
0e80      e80:	e9 00 00 00 00       	jmp    e85 <.altinstr_replacement+0xe85>	e81: R_X86_64_PC32	.text+0x2777d4
0e85      e85:	e9 00 00 00 00       	jmp    e8a <.altinstr_replacement+0xe8a>	e86: R_X86_64_PC32	.text+0x277b3e
0e8a      e8a:	e9 00 00 00 00       	jmp    e8f <.altinstr_replacement+0xe8f>	e8b: R_X86_64_PC32	.text+0x277bb8
0e8f      e8f:	e9 00 00 00 00       	jmp    e94 <.altinstr_replacement+0xe94>	e90: R_X86_64_PC32	.init.text+0x3e98e
0e94      e94:	e9 00 00 00 00       	jmp    e99 <.altinstr_replacement+0xe99>	e95: R_X86_64_PC32	.init.text+0x3e9c5
0e99      e99:	e9 00 00 00 00       	jmp    e9e <.altinstr_replacement+0xe9e>	e9a: R_X86_64_PC32	.init.text+0x3f1a4
0e9e      e9e:	e9 00 00 00 00       	jmp    ea3 <.altinstr_replacement+0xea3>	e9f: R_X86_64_PC32	.init.text+0x3f200
0ea3      ea3:	e9 00 00 00 00       	jmp    ea8 <.altinstr_replacement+0xea8>	ea4: R_X86_64_PC32	.init.text+0x3f2d2
0ea8      ea8:	e9 00 00 00 00       	jmp    ead <.altinstr_replacement+0xead>	ea9: R_X86_64_PC32	.init.text+0x3f2ef
0ead      ead:	e9 00 00 00 00       	jmp    eb2 <.altinstr_replacement+0xeb2>	eae: R_X86_64_PC32	.init.text+0x3f35c
0eb2      eb2:	e9 00 00 00 00       	jmp    eb7 <.altinstr_replacement+0xeb7>	eb3: R_X86_64_PC32	.init.text+0x3f72e
0eb7      eb7:	e9 00 00 00 00       	jmp    ebc <.altinstr_replacement+0xebc>	eb8: R_X86_64_PC32	.text+0x277df4
0ebc      ebc:	e9 00 00 00 00       	jmp    ec1 <.altinstr_replacement+0xec1>	ebd: R_X86_64_PC32	.text+0x277e59
0ec1      ec1:	e9 00 00 00 00       	jmp    ec6 <.altinstr_replacement+0xec6>	ec2: R_X86_64_PC32	.text+0x277e29
0ec6      ec6:	e9 00 00 00 00       	jmp    ecb <.altinstr_replacement+0xecb>	ec7: R_X86_64_PC32	.text+0x2780ef
0ecb      ecb:	e9 00 00 00 00       	jmp    ed0 <.altinstr_replacement+0xed0>	ecc: R_X86_64_PC32	.text+0x278112
0ed0      ed0:	e9 00 00 00 00       	jmp    ed5 <.altinstr_replacement+0xed5>	ed1: R_X86_64_PC32	.text+0x2781a4
0ed5      ed5:	e9 00 00 00 00       	jmp    eda <.altinstr_replacement+0xeda>	ed6: R_X86_64_PC32	.text+0x278203
0eda      eda:	e9 00 00 00 00       	jmp    edf <.altinstr_replacement+0xedf>	edb: R_X86_64_PC32	.text+0x27946d
0edf      edf:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
0ee9      ee9:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
0ef3      ef3:	48 ba 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rdx
0efd      efd:	48 ba 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rdx
0f07      f07:	48 ba 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rdx
0f11      f11:	48 ba 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rdx
0f1b      f1b:	48 ba 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rdx
0f25      f25:	48 ba 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rdx
0f2f      f2f:	48 ba 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rdx
0f39      f39:	e8 00 00 00 00       	call   f3e <.altinstr_replacement+0xf3e>	f3a: R_X86_64_PLT32	copy_user_generic_string-0x4
0f3e      f3e:	e8 00 00 00 00       	call   f43 <.altinstr_replacement+0xf43>	f3f: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
0f43      f43:	9c                   	pushf
0f44      f44:	58                   	pop    %rax
0f45      f45:	fa                   	cli
0f46      f46:	fb                   	sti
0f47      f47:	e9 00 00 00 00       	jmp    f4c <.altinstr_replacement+0xf4c>	f48: R_X86_64_PC32	.text.unlikely+0x233ff
0f4c      f4c:	48 89 f8             	mov    %rdi,%rax
0f4f      f4f:	e9 00 00 00 00       	jmp    f54 <.altinstr_replacement+0xf54>	f50: R_X86_64_PC32	.text.unlikely+0x23508
0f54      f54:	48 89 f8             	mov    %rdi,%rax
0f57      f57:	48 89 f8             	mov    %rdi,%rax
0f5a      f5a:	48 89 f8             	mov    %rdi,%rax
0f5d      f5d:	48 89 f8             	mov    %rdi,%rax
0f60      f60:	0f 22 df             	mov    %rdi,%cr3
0f63      f63:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
0f6d      f6d:	48 ba 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rdx
0f77      f77:	9c                   	pushf
0f78      f78:	58                   	pop    %rax
0f79      f79:	fa                   	cli
0f7a      f7a:	9c                   	pushf
0f7b      f7b:	58                   	pop    %rax
0f7c      f7c:	fb                   	sti
0f7d      f7d:	9c                   	pushf
0f7e      f7e:	58                   	pop    %rax
0f7f      f7f:	fa                   	cli
0f80      f80:	9c                   	pushf
0f81      f81:	58                   	pop    %rax
0f82      f82:	fb                   	sti
0f83      f83:	e9 00 00 00 00       	jmp    f88 <.altinstr_replacement+0xf88>	f84: R_X86_64_PC32	.text+0x284abf
0f88      f88:	e9 00 00 00 00       	jmp    f8d <.altinstr_replacement+0xf8d>	f89: R_X86_64_PC32	.text+0x284b67
0f8d      f8d:	e9 00 00 00 00       	jmp    f92 <.altinstr_replacement+0xf92>	f8e: R_X86_64_PC32	.text+0x284be7
0f92      f92:	e9 00 00 00 00       	jmp    f97 <.altinstr_replacement+0xf97>	f93: R_X86_64_PC32	.text+0x2862da
0f97      f97:	e9 00 00 00 00       	jmp    f9c <.altinstr_replacement+0xf9c>	f98: R_X86_64_PC32	.text+0x286368
0f9c      f9c:	e9 00 00 00 00       	jmp    fa1 <.altinstr_replacement+0xfa1>	f9d: R_X86_64_PC32	.text+0x286368
0fa1      fa1:	e9 00 00 00 00       	jmp    fa6 <.altinstr_replacement+0xfa6>	fa2: R_X86_64_PC32	.text+0x2863b0
0fa6      fa6:	e9 00 00 00 00       	jmp    fab <.altinstr_replacement+0xfab>	fa7: R_X86_64_PC32	.text+0x286368
0fab      fab:	e9 00 00 00 00       	jmp    fb0 <.altinstr_replacement+0xfb0>	fac: R_X86_64_PC32	.init.text+0x41934
0fb0      fb0:	e9 00 00 00 00       	jmp    fb5 <.altinstr_replacement+0xfb5>	fb1: R_X86_64_PC32	.text+0x28821c
0fb5      fb5:	e9 00 00 00 00       	jmp    fba <.altinstr_replacement+0xfba>	fb6: R_X86_64_PC32	.text+0x288237
0fba      fba:	e9 00 00 00 00       	jmp    fbf <.altinstr_replacement+0xfbf>	fbb: R_X86_64_PC32	.text+0x288243
0fbf      fbf:	e9 00 00 00 00       	jmp    fc4 <.altinstr_replacement+0xfc4>	fc0: R_X86_64_PC32	.text+0x28829c
0fc4      fc4:	e9 00 00 00 00       	jmp    fc9 <.altinstr_replacement+0xfc9>	fc5: R_X86_64_PC32	.text+0x28999d
0fc9      fc9:	e9 00 00 00 00       	jmp    fce <.altinstr_replacement+0xfce>	fca: R_X86_64_PC32	.init.text+0x464dd
0fce      fce:	e9 00 00 00 00       	jmp    fd3 <.altinstr_replacement+0xfd3>	fcf: R_X86_64_PC32	.init.text+0x464fa
0fd3      fd3:	e9 00 00 00 00       	jmp    fd8 <.altinstr_replacement+0xfd8>	fd4: R_X86_64_PC32	.init.text+0x4772d
0fd8      fd8:	e9 00 00 00 00       	jmp    fdd <.altinstr_replacement+0xfdd>	fd9: R_X86_64_PC32	.text+0x28b589
0fdd      fdd:	e9 00 00 00 00       	jmp    fe2 <.altinstr_replacement+0xfe2>	fde: R_X86_64_PC32	.text+0x28b769
0fe2      fe2:	e9 00 00 00 00       	jmp    fe7 <.altinstr_replacement+0xfe7>	fe3: R_X86_64_PC32	.text+0x28b874
0fe7      fe7:	9c                   	pushf
0fe8      fe8:	58                   	pop    %rax
0fe9      fe9:	fa                   	cli
0fea      fea:	fb                   	sti
0feb      feb:	e9 00 00 00 00       	jmp    ff0 <.altinstr_replacement+0xff0>	fec: R_X86_64_PC32	.text+0x291015
0ff0      ff0:	e9 00 00 00 00       	jmp    ff5 <.altinstr_replacement+0xff5>	ff1: R_X86_64_PC32	.text+0x291371
0ff5      ff5:	e9 00 00 00 00       	jmp    ffa <.altinstr_replacement+0xffa>	ff6: R_X86_64_PC32	.text+0x297993
0ffa      ffa:	e9 00 00 00 00       	jmp    fff <.altinstr_replacement+0xfff>	ffb: R_X86_64_PC32	.text+0x297e9f
0fff      fff:	e9 00 00 00 00       	jmp    1004 <.altinstr_replacement+0x1004>	1000: R_X86_64_PC32	.text+0x297f67
1004     1004:	e9 00 00 00 00       	jmp    1009 <.altinstr_replacement+0x1009>	1005: R_X86_64_PC32	.text+0x297f79
1009     1009:	fb                   	sti
100a     100a:	9c                   	pushf
100b     100b:	58                   	pop    %rax
100c     100c:	fa                   	cli
100d     100d:	9c                   	pushf
100e     100e:	58                   	pop    %rax
100f     100f:	fb                   	sti
1010     1010:	9c                   	pushf
1011     1011:	58                   	pop    %rax
1012     1012:	fa                   	cli
1013     1013:	9c                   	pushf
1014     1014:	58                   	pop    %rax
1015     1015:	fb                   	sti
1016     1016:	e9 00 00 00 00       	jmp    101b <.altinstr_replacement+0x101b>	1017: R_X86_64_PC32	.text+0x29bc20
101b     101b:	e9 00 00 00 00       	jmp    1020 <.altinstr_replacement+0x1020>	101c: R_X86_64_PC32	.text+0x29bc32
1020     1020:	e9 00 00 00 00       	jmp    1025 <.altinstr_replacement+0x1025>	1021: R_X86_64_PC32	.text+0x29c142
1025     1025:	e9 00 00 00 00       	jmp    102a <.altinstr_replacement+0x102a>	1026: R_X86_64_PC32	.text+0x29c55b
102a     102a:	e9 00 00 00 00       	jmp    102f <.altinstr_replacement+0x102f>	102b: R_X86_64_PC32	.noinstr.text+0x5509
102f     102f:	e9 00 00 00 00       	jmp    1034 <.altinstr_replacement+0x1034>	1030: R_X86_64_PC32	.noinstr.text+0x541c
1034     1034:	e9 00 00 00 00       	jmp    1039 <.altinstr_replacement+0x1039>	1035: R_X86_64_PC32	.text+0x29d364
1039     1039:	e9 00 00 00 00       	jmp    103e <.altinstr_replacement+0x103e>	103a: R_X86_64_PC32	.text+0x29d371
103e     103e:	e9 00 00 00 00       	jmp    1043 <.altinstr_replacement+0x1043>	103f: R_X86_64_PC32	.text+0x29d37e
1043     1043:	e9 00 00 00 00       	jmp    1048 <.altinstr_replacement+0x1048>	1044: R_X86_64_PC32	.noinstr.text+0x607f
1048     1048:	e9 00 00 00 00       	jmp    104d <.altinstr_replacement+0x104d>	1049: R_X86_64_PC32	.noinstr.text+0x60e0
104d     104d:	e9 00 00 00 00       	jmp    1052 <.altinstr_replacement+0x1052>	104e: R_X86_64_PC32	.noinstr.text+0x60f2
1052     1052:	e9 00 00 00 00       	jmp    1057 <.altinstr_replacement+0x1057>	1053: R_X86_64_PC32	.init.text+0x49531
1057     1057:	e9 00 00 00 00       	jmp    105c <.altinstr_replacement+0x105c>	1058: R_X86_64_PC32	.noinstr.text+0x64c1
105c     105c:	e9 00 00 00 00       	jmp    1061 <.altinstr_replacement+0x1061>	105d: R_X86_64_PC32	.noinstr.text+0x6683
1061     1061:	e9 00 00 00 00       	jmp    1066 <.altinstr_replacement+0x1066>	1062: R_X86_64_PC32	.text+0x29dfd6
1066     1066:	9c                   	pushf
1067     1067:	58                   	pop    %rax
1068     1068:	fa                   	cli
1069     1069:	9c                   	pushf
106a     106a:	58                   	pop    %rax
106b     106b:	fb                   	sti
106c     106c:	e9 00 00 00 00       	jmp    1071 <.altinstr_replacement+0x1071>	106d: R_X86_64_PC32	.text+0x2a1ae3
1071     1071:	e9 00 00 00 00       	jmp    1076 <.altinstr_replacement+0x1076>	1072: R_X86_64_PC32	.text+0x2a3386
1076     1076:	e9 00 00 00 00       	jmp    107b <.altinstr_replacement+0x107b>	1077: R_X86_64_PC32	.text+0x2a3375
107b     107b:	e9 00 00 00 00       	jmp    1080 <.altinstr_replacement+0x1080>	107c: R_X86_64_PC32	.text+0x2a3fcd
1080     1080:	e9 00 00 00 00       	jmp    1085 <.altinstr_replacement+0x1085>	1081: R_X86_64_PC32	.text+0x2a457d
1085     1085:	e9 00 00 00 00       	jmp    108a <.altinstr_replacement+0x108a>	1086: R_X86_64_PC32	.text+0x2a458f
108a     108a:	e9 00 00 00 00       	jmp    108f <.altinstr_replacement+0x108f>	108b: R_X86_64_PC32	.text+0x2a6386
108f     108f:	9c                   	pushf
1090     1090:	58                   	pop    %rax
1091     1091:	fa                   	cli
1092     1092:	9c                   	pushf
1093     1093:	58                   	pop    %rax
1094     1094:	fb                   	sti
1095     1095:	9c                   	pushf
1096     1096:	58                   	pop    %rax
1097     1097:	fa                   	cli
1098     1098:	9c                   	pushf
1099     1099:	58                   	pop    %rax
109a     109a:	fb                   	sti
109b     109b:	e9 00 00 00 00       	jmp    10a0 <.altinstr_replacement+0x10a0>	109c: R_X86_64_PC32	.text.unlikely+0x25651
10a0     10a0:	e9 00 00 00 00       	jmp    10a5 <.altinstr_replacement+0x10a5>	10a1: R_X86_64_PC32	.text.unlikely+0x25555
10a5     10a5:	e9 00 00 00 00       	jmp    10aa <.altinstr_replacement+0x10aa>	10a6: R_X86_64_PC32	.text.unlikely+0x255a9
10aa     10aa:	0f ae e8             	lfence
10ad     10ad:	0f 31                	rdtsc
10af     10af:	0f 01 f9             	rdtscp
10b2     10b2:	e9 00 00 00 00       	jmp    10b7 <.altinstr_replacement+0x10b7>	10b3: R_X86_64_PC32	.text+0x2a7dfa
10b7     10b7:	e9 00 00 00 00       	jmp    10bc <.altinstr_replacement+0x10bc>	10b8: R_X86_64_PC32	.text+0x2aeeca
10bc     10bc:	e9 00 00 00 00       	jmp    10c1 <.altinstr_replacement+0x10c1>	10bd: R_X86_64_PC32	.text+0x2aeef9
10c1     10c1:	0f 09                	wbinvd
10c3     10c3:	0f 09                	wbinvd
10c5     10c5:	9c                   	pushf
10c6     10c6:	58                   	pop    %rax
10c7     10c7:	fa                   	cli
10c8     10c8:	9c                   	pushf
10c9     10c9:	58                   	pop    %rax
10ca     10ca:	fb                   	sti
10cb     10cb:	9c                   	pushf
10cc     10cc:	58                   	pop    %rax
10cd     10cd:	fa                   	cli
10ce     10ce:	9c                   	pushf
10cf     10cf:	58                   	pop    %rax
10d0     10d0:	fb                   	sti
10d1     10d1:	9c                   	pushf
10d2     10d2:	58                   	pop    %rax
10d3     10d3:	fa                   	cli
10d4     10d4:	9c                   	pushf
10d5     10d5:	58                   	pop    %rax
10d6     10d6:	fb                   	sti
10d7     10d7:	9c                   	pushf
10d8     10d8:	58                   	pop    %rax
10d9     10d9:	fa                   	cli
10da     10da:	fb                   	sti
10db     10db:	9c                   	pushf
10dc     10dc:	58                   	pop    %rax
10dd     10dd:	fa                   	cli
10de     10de:	0f ae e8             	lfence
10e1     10e1:	0f 31                	rdtsc
10e3     10e3:	0f 01 f9             	rdtscp
10e6     10e6:	0f ae e8             	lfence
10e9     10e9:	0f 31                	rdtsc
10eb     10eb:	0f 01 f9             	rdtscp
10ee     10ee:	0f ae e8             	lfence
10f1     10f1:	0f 31                	rdtsc
10f3     10f3:	0f 01 f9             	rdtscp
10f6     10f6:	fb                   	sti
10f7     10f7:	9c                   	pushf
10f8     10f8:	58                   	pop    %rax
10f9     10f9:	fa                   	cli
10fa     10fa:	fb                   	sti
10fb     10fb:	fb                   	sti
10fc     10fc:	e9 00 00 00 00       	jmp    1101 <.altinstr_replacement+0x1101>	10fd: R_X86_64_PC32	.init.text+0x53c55
1101     1101:	e9 00 00 00 00       	jmp    1106 <.altinstr_replacement+0x1106>	1102: R_X86_64_PC32	.init.text+0x53d99
1106     1106:	e9 00 00 00 00       	jmp    110b <.altinstr_replacement+0x110b>	1107: R_X86_64_PC32	.text+0x2d097f
110b     110b:	e9 00 00 00 00       	jmp    1110 <.altinstr_replacement+0x1110>	110c: R_X86_64_PC32	.text+0x2d1261
1110     1110:	e9 00 00 00 00       	jmp    1115 <.altinstr_replacement+0x1115>	1111: R_X86_64_PC32	.init.text+0x547bc
1115     1115:	9c                   	pushf
1116     1116:	58                   	pop    %rax
1117     1117:	49 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r13
1121     1121:	0f 01 cb             	stac
1124     1124:	0f 01 ca             	clac
1127     1127:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
1131     1131:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
113b     113b:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
1145     1145:	0f 01 cb             	stac
1148     1148:	0f 01 ca             	clac
114b     114b:	e9 00 00 00 00       	jmp    1150 <.altinstr_replacement+0x1150>	114c: R_X86_64_PC32	.text+0x2d84bf
1150     1150:	e9 00 00 00 00       	jmp    1155 <.altinstr_replacement+0x1155>	1151: R_X86_64_PC32	.init.text+0x54b0b
1155     1155:	0f 01 c1             	vmcall
1158     1158:	0f 01 d9             	vmmcall
115b     115b:	9c                   	pushf
115c     115c:	58                   	pop    %rax
115d     115d:	fa                   	cli
115e     115e:	fb                   	sti
115f     115f:	9c                   	pushf
1160     1160:	58                   	pop    %rax
1161     1161:	fa                   	cli
1162     1162:	fb                   	sti
1163     1163:	e9 00 00 00 00       	jmp    1168 <.altinstr_replacement+0x1168>	1164: R_X86_64_PC32	.text+0x2dce79
1168     1168:	e9 00 00 00 00       	jmp    116d <.altinstr_replacement+0x116d>	1169: R_X86_64_PC32	.text+0x2dd947
116d     116d:	e9 00 00 00 00       	jmp    1172 <.altinstr_replacement+0x1172>	116e: R_X86_64_PC32	.text+0x2dd873
1172     1172:	9c                   	pushf
1173     1173:	58                   	pop    %rax
1174     1174:	fa                   	cli
1175     1175:	9c                   	pushf
1176     1176:	58                   	pop    %rax
1177     1177:	fa                   	cli
1178     1178:	9c                   	pushf
1179     1179:	58                   	pop    %rax
117a     117a:	fa                   	cli
117b     117b:	9c                   	pushf
117c     117c:	58                   	pop    %rax
117d     117d:	fa                   	cli
117e     117e:	9c                   	pushf
117f     117f:	58                   	pop    %rax
1180     1180:	fb                   	sti
1181     1181:	9c                   	pushf
1182     1182:	58                   	pop    %rax
1183     1183:	fa                   	cli
1184     1184:	9c                   	pushf
1185     1185:	58                   	pop    %rax
1186     1186:	fa                   	cli
1187     1187:	9c                   	pushf
1188     1188:	58                   	pop    %rax
1189     1189:	fa                   	cli
118a     118a:	9c                   	pushf
118b     118b:	58                   	pop    %rax
118c     118c:	fb                   	sti
118d     118d:	9c                   	pushf
118e     118e:	58                   	pop    %rax
118f     118f:	fa                   	cli
1190     1190:	9c                   	pushf
1191     1191:	58                   	pop    %rax
1192     1192:	fb                   	sti
1193     1193:	0f 09                	wbinvd
1195     1195:	fb                   	sti
1196     1196:	9c                   	pushf
1197     1197:	58                   	pop    %rax
1198     1198:	fa                   	cli
1199     1199:	9c                   	pushf
119a     119a:	58                   	pop    %rax
119b     119b:	fb                   	sti
119c     119c:	e9 00 00 00 00       	jmp    11a1 <.altinstr_replacement+0x11a1>	119d: R_X86_64_PC32	.init.text+0x5f888
11a1     11a1:	9c                   	pushf
11a2     11a2:	58                   	pop    %rax
11a3     11a3:	fa                   	cli
11a4     11a4:	0f 09                	wbinvd
11a6     11a6:	e9 00 00 00 00       	jmp    11ab <.altinstr_replacement+0x11ab>	11a7: R_X86_64_PC32	.init.text+0x5fed5
11ab     11ab:	0f ae e8             	lfence
11ae     11ae:	0f 31                	rdtsc
11b0     11b0:	0f 01 f9             	rdtscp
11b3     11b3:	0f ae e8             	lfence
11b6     11b6:	0f 31                	rdtsc
11b8     11b8:	0f 01 f9             	rdtscp
11bb     11bb:	c6 07 00             	movb   $0x0,(%rdi)
11be     11be:	c6 07 00             	movb   $0x0,(%rdi)
11c1     11c1:	9c                   	pushf
11c2     11c2:	58                   	pop    %rax
11c3     11c3:	fa                   	cli
11c4     11c4:	fb                   	sti
11c5     11c5:	9c                   	pushf
11c6     11c6:	58                   	pop    %rax
11c7     11c7:	fa                   	cli
11c8     11c8:	fb                   	sti
11c9     11c9:	9c                   	pushf
11ca     11ca:	58                   	pop    %rax
11cb     11cb:	fa                   	cli
11cc     11cc:	fb                   	sti
11cd     11cd:	fb                   	sti
11ce     11ce:	9c                   	pushf
11cf     11cf:	58                   	pop    %rax
11d0     11d0:	fa                   	cli
11d1     11d1:	fb                   	sti
11d2     11d2:	9c                   	pushf
11d3     11d3:	58                   	pop    %rax
11d4     11d4:	fa                   	cli
11d5     11d5:	9c                   	pushf
11d6     11d6:	58                   	pop    %rax
11d7     11d7:	fb                   	sti
11d8     11d8:	9c                   	pushf
11d9     11d9:	58                   	pop    %rax
11da     11da:	fa                   	cli
11db     11db:	9c                   	pushf
11dc     11dc:	58                   	pop    %rax
11dd     11dd:	fb                   	sti
11de     11de:	9c                   	pushf
11df     11df:	58                   	pop    %rax
11e0     11e0:	fa                   	cli
11e1     11e1:	9c                   	pushf
11e2     11e2:	58                   	pop    %rax
11e3     11e3:	fb                   	sti
11e4     11e4:	9c                   	pushf
11e5     11e5:	58                   	pop    %rax
11e6     11e6:	fa                   	cli
11e7     11e7:	9c                   	pushf
11e8     11e8:	58                   	pop    %rax
11e9     11e9:	fb                   	sti
11ea     11ea:	9c                   	pushf
11eb     11eb:	58                   	pop    %rax
11ec     11ec:	fa                   	cli
11ed     11ed:	9c                   	pushf
11ee     11ee:	58                   	pop    %rax
11ef     11ef:	fb                   	sti
11f0     11f0:	87 34 25 00 c3 5f ff 	xchg   %esi,0xffffffffff5fc300
11f7     11f7:	87 04 25 10 c3 5f ff 	xchg   %eax,0xffffffffff5fc310
11fe     11fe:	87 04 25 00 c3 5f ff 	xchg   %eax,0xffffffffff5fc300
1205     1205:	9c                   	pushf
1206     1206:	58                   	pop    %rax
1207     1207:	fa                   	cli
1208     1208:	9c                   	pushf
1209     1209:	58                   	pop    %rax
120a     120a:	fb                   	sti
120b     120b:	9c                   	pushf
120c     120c:	58                   	pop    %rax
120d     120d:	fa                   	cli
120e     120e:	9c                   	pushf
120f     120f:	58                   	pop    %rax
1210     1210:	fb                   	sti
1211     1211:	9c                   	pushf
1212     1212:	58                   	pop    %rax
1213     1213:	fa                   	cli
1214     1214:	9c                   	pushf
1215     1215:	58                   	pop    %rax
1216     1216:	fb                   	sti
1217     1217:	87 3c 25 00 c3 5f ff 	xchg   %edi,0xffffffffff5fc300
121e     121e:	87 3c 25 00 c3 5f ff 	xchg   %edi,0xffffffffff5fc300
1225     1225:	87 3c 25 00 c3 5f ff 	xchg   %edi,0xffffffffff5fc300
122c     122c:	fb                   	sti
122d     122d:	9c                   	pushf
122e     122e:	58                   	pop    %rax
122f     122f:	fa                   	cli
1230     1230:	9c                   	pushf
1231     1231:	58                   	pop    %rax
1232     1232:	fa                   	cli
1233     1233:	fb                   	sti
1234     1234:	9c                   	pushf
1235     1235:	58                   	pop    %rax
1236     1236:	fa                   	cli
1237     1237:	9c                   	pushf
1238     1238:	58                   	pop    %rax
1239     1239:	fb                   	sti
123a     123a:	87 b7 00 c0 5f ff    	xchg   %esi,-0xa04000(%rdi)
1240     1240:	e9 00 00 00 00       	jmp    1245 <.altinstr_replacement+0x1245>	1241: R_X86_64_PC32	.text+0x2f627f
1245     1245:	9c                   	pushf
1246     1246:	58                   	pop    %rax
1247     1247:	fa                   	cli
1248     1248:	9c                   	pushf
1249     1249:	58                   	pop    %rax
124a     124a:	fb                   	sti
124b     124b:	f3 48 0f b8 c7       	popcnt %rdi,%rax
1250     1250:	f3 48 0f b8 c7       	popcnt %rdi,%rax
1255     1255:	f3 48 0f b8 c7       	popcnt %rdi,%rax
125a     125a:	9c                   	pushf
125b     125b:	58                   	pop    %rax
125c     125c:	fa                   	cli
125d     125d:	9c                   	pushf
125e     125e:	58                   	pop    %rax
125f     125f:	fb                   	sti
1260     1260:	9c                   	pushf
1261     1261:	58                   	pop    %rax
1262     1262:	fa                   	cli
1263     1263:	9c                   	pushf
1264     1264:	58                   	pop    %rax
1265     1265:	fb                   	sti
1266     1266:	87 b7 00 c0 5f ff    	xchg   %esi,-0xa04000(%rdi)
126c     126c:	9c                   	pushf
126d     126d:	58                   	pop    %rax
126e     126e:	fa                   	cli
126f     126f:	9c                   	pushf
1270     1270:	58                   	pop    %rax
1271     1271:	fb                   	sti
1272     1272:	e9 00 00 00 00       	jmp    1277 <.altinstr_replacement+0x1277>	1273: R_X86_64_PC32	.text+0x2fa47d
1277     1277:	0f ae e8             	lfence
127a     127a:	0f 31                	rdtsc
127c     127c:	0f 01 f9             	rdtscp
127f     127f:	e9 00 00 00 00       	jmp    1284 <.altinstr_replacement+0x1284>	1280: R_X86_64_PC32	.text+0x2fc0e5
1284     1284:	e8 00 00 00 00       	call   1289 <.altinstr_replacement+0x1289>	1285: R_X86_64_PLT32	clear_page_rep-0x4
1289     1289:	e8 00 00 00 00       	call   128e <.altinstr_replacement+0x128e>	128a: R_X86_64_PLT32	clear_page_erms-0x4
128e     128e:	e9 00 00 00 00       	jmp    1293 <.altinstr_replacement+0x1293>	128f: R_X86_64_PC32	.text+0x2fc38f
1293     1293:	48 89 f8             	mov    %rdi,%rax
1296     1296:	48 89 f8             	mov    %rdi,%rax
1299     1299:	e9 00 00 00 00       	jmp    129e <.altinstr_replacement+0x129e>	129a: R_X86_64_PC32	.text+0x2fc870
129e     129e:	e9 00 00 00 00       	jmp    12a3 <.altinstr_replacement+0x12a3>	129f: R_X86_64_PC32	.text+0x2fcd0b
12a3     12a3:	48 89 f8             	mov    %rdi,%rax
12a6     12a6:	48 89 f8             	mov    %rdi,%rax
12a9     12a9:	48 89 f8             	mov    %rdi,%rax
12ac     12ac:	48 89 f8             	mov    %rdi,%rax
12af     12af:	48 89 f8             	mov    %rdi,%rax
12b2     12b2:	48 89 f8             	mov    %rdi,%rax
12b5     12b5:	48 89 f8             	mov    %rdi,%rax
12b8     12b8:	48 89 f8             	mov    %rdi,%rax
12bb     12bb:	e8 00 00 00 00       	call   12c0 <.altinstr_replacement+0x12c0>	12bc: R_X86_64_PLT32	clear_page_rep-0x4
12c0     12c0:	e8 00 00 00 00       	call   12c5 <.altinstr_replacement+0x12c5>	12c1: R_X86_64_PLT32	clear_page_erms-0x4
12c5     12c5:	9c                   	pushf
12c6     12c6:	58                   	pop    %rax
12c7     12c7:	fa                   	cli
12c8     12c8:	9c                   	pushf
12c9     12c9:	58                   	pop    %rax
12ca     12ca:	fa                   	cli
12cb     12cb:	9c                   	pushf
12cc     12cc:	58                   	pop    %rax
12cd     12cd:	fb                   	sti
12ce     12ce:	9c                   	pushf
12cf     12cf:	58                   	pop    %rax
12d0     12d0:	fa                   	cli
12d1     12d1:	e9 00 00 00 00       	jmp    12d6 <.altinstr_replacement+0x12d6>	12d2: R_X86_64_PC32	.text+0x2ffd27
12d6     12d6:	9c                   	pushf
12d7     12d7:	58                   	pop    %rax
12d8     12d8:	fa                   	cli
12d9     12d9:	9c                   	pushf
12da     12da:	58                   	pop    %rax
12db     12db:	fb                   	sti
12dc     12dc:	9c                   	pushf
12dd     12dd:	58                   	pop    %rax
12de     12de:	fa                   	cli
12df     12df:	c6 07 00             	movb   $0x0,(%rdi)
12e2     12e2:	9c                   	pushf
12e3     12e3:	58                   	pop    %rax
12e4     12e4:	fb                   	sti
12e5     12e5:	9c                   	pushf
12e6     12e6:	58                   	pop    %rax
12e7     12e7:	fb                   	sti
12e8     12e8:	e9 00 00 00 00       	jmp    12ed <.altinstr_replacement+0x12ed>	12e9: R_X86_64_PC32	.init.text+0x74526
12ed     12ed:	9c                   	pushf
12ee     12ee:	58                   	pop    %rax
12ef     12ef:	fa                   	cli
12f0     12f0:	9c                   	pushf
12f1     12f1:	58                   	pop    %rax
12f2     12f2:	fb                   	sti
12f3     12f3:	9c                   	pushf
12f4     12f4:	58                   	pop    %rax
12f5     12f5:	9c                   	pushf
12f6     12f6:	58                   	pop    %rax
12f7     12f7:	fa                   	cli
12f8     12f8:	fb                   	sti
12f9     12f9:	fb                   	sti
12fa     12fa:	9c                   	pushf
12fb     12fb:	58                   	pop    %rax
12fc     12fc:	fa                   	cli
12fd     12fd:	e9 00 00 00 00       	jmp    1302 <.altinstr_replacement+0x1302>	12fe: R_X86_64_PC32	.text+0x30b453
1302     1302:	0f 01 d9             	vmmcall
1305     1305:	48 31 c0             	xor    %rax,%rax
1308     1308:	e9 00 00 00 00       	jmp    130d <.altinstr_replacement+0x130d>	1309: R_X86_64_PC32	.text+0x30bf31
130d     130d:	0f 01 d9             	vmmcall
1310     1310:	9c                   	pushf
1311     1311:	58                   	pop    %rax
1312     1312:	fa                   	cli
1313     1313:	e9 00 00 00 00       	jmp    1318 <.altinstr_replacement+0x1318>	1314: R_X86_64_PC32	.text+0x30c45d
1318     1318:	9c                   	pushf
1319     1319:	58                   	pop    %rax
131a     131a:	fb                   	sti
131b     131b:	0f 01 d9             	vmmcall
131e     131e:	e9 00 00 00 00       	jmp    1323 <.altinstr_replacement+0x1323>	131f: R_X86_64_PC32	.text+0x30c534
1323     1323:	0f 01 d9             	vmmcall
1326     1326:	9c                   	pushf
1327     1327:	58                   	pop    %rax
1328     1328:	fa                   	cli
1329     1329:	9c                   	pushf
132a     132a:	58                   	pop    %rax
132b     132b:	fb                   	sti
132c     132c:	9c                   	pushf
132d     132d:	58                   	pop    %rax
132e     132e:	fa                   	cli
132f     132f:	9c                   	pushf
1330     1330:	58                   	pop    %rax
1331     1331:	fb                   	sti
1332     1332:	e9 00 00 00 00       	jmp    1337 <.altinstr_replacement+0x1337>	1333: R_X86_64_PC32	.text+0x30dd98
1337     1337:	e9 00 00 00 00       	jmp    133c <.altinstr_replacement+0x133c>	1338: R_X86_64_PC32	.text+0x30dda5
133c     133c:	9c                   	pushf
133d     133d:	58                   	pop    %rax
133e     133e:	fa                   	cli
133f     133f:	9c                   	pushf
1340     1340:	58                   	pop    %rax
1341     1341:	fb                   	sti
1342     1342:	e9 00 00 00 00       	jmp    1347 <.altinstr_replacement+0x1347>	1343: R_X86_64_PC32	.text+0x30e491
1347     1347:	9c                   	pushf
1348     1348:	58                   	pop    %rax
1349     1349:	9c                   	pushf
134a     134a:	58                   	pop    %rax
134b     134b:	0f ae e8             	lfence
134e     134e:	0f 31                	rdtsc
1350     1350:	0f 01 f9             	rdtscp
1353     1353:	9c                   	pushf
1354     1354:	58                   	pop    %rax
1355     1355:	9c                   	pushf
1356     1356:	58                   	pop    %rax
1357     1357:	9c                   	pushf
1358     1358:	58                   	pop    %rax
1359     1359:	fa                   	cli
135a     135a:	9c                   	pushf
135b     135b:	58                   	pop    %rax
135c     135c:	fb                   	sti
135d     135d:	9c                   	pushf
135e     135e:	58                   	pop    %rax
135f     135f:	fa                   	cli
1360     1360:	9c                   	pushf
1361     1361:	58                   	pop    %rax
1362     1362:	fb                   	sti
1363     1363:	9c                   	pushf
1364     1364:	58                   	pop    %rax
1365     1365:	fa                   	cli
1366     1366:	9c                   	pushf
1367     1367:	58                   	pop    %rax
1368     1368:	fb                   	sti
1369     1369:	9c                   	pushf
136a     136a:	58                   	pop    %rax
136b     136b:	fa                   	cli
136c     136c:	9c                   	pushf
136d     136d:	58                   	pop    %rax
136e     136e:	fb                   	sti
136f     136f:	0f 20 d8             	mov    %cr3,%rax
1372     1372:	48 89 f8             	mov    %rdi,%rax
1375     1375:	48 89 f8             	mov    %rdi,%rax
1378     1378:	0f 09                	wbinvd
137a     137a:	f3 0f b8 c7          	popcnt %edi,%eax
137e     137e:	9c                   	pushf
137f     137f:	58                   	pop    %rax
1380     1380:	fa                   	cli
1381     1381:	9c                   	pushf
1382     1382:	58                   	pop    %rax
1383     1383:	fb                   	sti
1384     1384:	e9 00 00 00 00       	jmp    1389 <.altinstr_replacement+0x1389>	1385: R_X86_64_PC32	.init.text+0x7e58e
1389     1389:	e8 00 00 00 00       	call   138e <.altinstr_replacement+0x138e>	138a: R_X86_64_PLT32	clear_page_rep-0x4
138e     138e:	e8 00 00 00 00       	call   1393 <.altinstr_replacement+0x1393>	138f: R_X86_64_PLT32	clear_page_erms-0x4
1393     1393:	0f 22 df             	mov    %rdi,%cr3
1396     1396:	e9 00 00 00 00       	jmp    139b <.altinstr_replacement+0x139b>	1397: R_X86_64_PC32	.text+0x319481
139b     139b:	e9 00 00 00 00       	jmp    13a0 <.altinstr_replacement+0x13a0>	139c: R_X86_64_PC32	.text+0x319b39
13a0     13a0:	e9 00 00 00 00       	jmp    13a5 <.altinstr_replacement+0x13a5>	13a1: R_X86_64_PC32	.text+0x319c40
13a5     13a5:	48 89 f8             	mov    %rdi,%rax
13a8     13a8:	48 89 f8             	mov    %rdi,%rax
13ab     13ab:	48 89 f8             	mov    %rdi,%rax
13ae     13ae:	48 89 f8             	mov    %rdi,%rax
13b1     13b1:	48 89 f8             	mov    %rdi,%rax
13b4     13b4:	48 89 f8             	mov    %rdi,%rax
13b7     13b7:	48 89 f8             	mov    %rdi,%rax
13ba     13ba:	48 89 f8             	mov    %rdi,%rax
13bd     13bd:	48 89 f8             	mov    %rdi,%rax
13c0     13c0:	48 89 f8             	mov    %rdi,%rax
13c3     13c3:	e9 00 00 00 00       	jmp    13c8 <.altinstr_replacement+0x13c8>	13c4: R_X86_64_PC32	.text.unlikely+0x2bb3b
13c8     13c8:	e9 00 00 00 00       	jmp    13cd <.altinstr_replacement+0x13cd>	13c9: R_X86_64_PC32	.text.unlikely+0x2bb01
13cd     13cd:	e9 00 00 00 00       	jmp    13d2 <.altinstr_replacement+0x13d2>	13ce: R_X86_64_PC32	.text.unlikely+0x2bc7f
13d2     13d2:	e9 00 00 00 00       	jmp    13d7 <.altinstr_replacement+0x13d7>	13d3: R_X86_64_PC32	.text.unlikely+0x2bc45
13d7     13d7:	48 89 f8             	mov    %rdi,%rax
13da     13da:	48 89 f8             	mov    %rdi,%rax
13dd     13dd:	48 89 f8             	mov    %rdi,%rax
13e0     13e0:	48 89 f8             	mov    %rdi,%rax
13e3     13e3:	48 89 f8             	mov    %rdi,%rax
13e6     13e6:	e9 00 00 00 00       	jmp    13eb <.altinstr_replacement+0x13eb>	13e7: R_X86_64_PC32	.text.unlikely+0x2c314
13eb     13eb:	48 89 f8             	mov    %rdi,%rax
13ee     13ee:	48 89 f8             	mov    %rdi,%rax
13f1     13f1:	e9 00 00 00 00       	jmp    13f6 <.altinstr_replacement+0x13f6>	13f2: R_X86_64_PC32	.meminit.text+0x2374
13f6     13f6:	48 89 f8             	mov    %rdi,%rax
13f9     13f9:	e9 00 00 00 00       	jmp    13fe <.altinstr_replacement+0x13fe>	13fa: R_X86_64_PC32	.meminit.text+0x33ae
13fe     13fe:	48 89 f8             	mov    %rdi,%rax
1401     1401:	e9 00 00 00 00       	jmp    1406 <.altinstr_replacement+0x1406>	1402: R_X86_64_PC32	.text+0x31b3de
1406     1406:	48 89 f8             	mov    %rdi,%rax
1409     1409:	e9 00 00 00 00       	jmp    140e <.altinstr_replacement+0x140e>	140a: R_X86_64_PC32	.init.text+0x7fc02
140e     140e:	e9 00 00 00 00       	jmp    1413 <.altinstr_replacement+0x1413>	140f: R_X86_64_PC32	.text.unlikely+0x2c7c0
1413     1413:	e9 00 00 00 00       	jmp    1418 <.altinstr_replacement+0x1418>	1414: R_X86_64_PC32	.meminit.text+0x3af1
1418     1418:	e9 00 00 00 00       	jmp    141d <.altinstr_replacement+0x141d>	1419: R_X86_64_PC32	.init.text+0x7fec4
141d     141d:	e9 00 00 00 00       	jmp    1422 <.altinstr_replacement+0x1422>	141e: R_X86_64_PC32	.init.text+0x80001
1422     1422:	48 89 f8             	mov    %rdi,%rax
1425     1425:	48 89 f8             	mov    %rdi,%rax
1428     1428:	48 89 f8             	mov    %rdi,%rax
142b     142b:	48 89 f8             	mov    %rdi,%rax
142e     142e:	48 89 f8             	mov    %rdi,%rax
1431     1431:	48 89 f8             	mov    %rdi,%rax
1434     1434:	48 89 f8             	mov    %rdi,%rax
1437     1437:	48 89 f8             	mov    %rdi,%rax
143a     143a:	48 89 f8             	mov    %rdi,%rax
143d     143d:	48 89 f8             	mov    %rdi,%rax
1440     1440:	48 89 f8             	mov    %rdi,%rax
1443     1443:	48 89 f8             	mov    %rdi,%rax
1446     1446:	48 89 f8             	mov    %rdi,%rax
1449     1449:	48 89 f8             	mov    %rdi,%rax
144c     144c:	e9 00 00 00 00       	jmp    1451 <.altinstr_replacement+0x1451>	144d: R_X86_64_PC32	.text+0x31c614
1451     1451:	e9 00 00 00 00       	jmp    1456 <.altinstr_replacement+0x1456>	1452: R_X86_64_PC32	.text+0x31c674
1456     1456:	e9 00 00 00 00       	jmp    145b <.altinstr_replacement+0x145b>	1457: R_X86_64_PC32	.text+0x31c74c
145b     145b:	48 89 f8             	mov    %rdi,%rax
145e     145e:	48 89 f8             	mov    %rdi,%rax
1461     1461:	e9 00 00 00 00       	jmp    1466 <.altinstr_replacement+0x1466>	1462: R_X86_64_PC32	.text+0x31c7c5
1466     1466:	48 89 f8             	mov    %rdi,%rax
1469     1469:	48 89 f8             	mov    %rdi,%rax
146c     146c:	48 89 f8             	mov    %rdi,%rax
146f     146f:	e9 00 00 00 00       	jmp    1474 <.altinstr_replacement+0x1474>	1470: R_X86_64_PC32	.text+0x31cc2f
1474     1474:	e9 00 00 00 00       	jmp    1479 <.altinstr_replacement+0x1479>	1475: R_X86_64_PC32	.text+0x31ceec
1479     1479:	e9 00 00 00 00       	jmp    147e <.altinstr_replacement+0x147e>	147a: R_X86_64_PC32	.text+0x31cf75
147e     147e:	48 89 f8             	mov    %rdi,%rax
1481     1481:	48 89 f8             	mov    %rdi,%rax
1484     1484:	48 89 f8             	mov    %rdi,%rax
1487     1487:	48 89 f8             	mov    %rdi,%rax
148a     148a:	48 89 f8             	mov    %rdi,%rax
148d     148d:	e9 00 00 00 00       	jmp    1492 <.altinstr_replacement+0x1492>	148e: R_X86_64_PC32	.text+0x31d8cd
1492     1492:	e9 00 00 00 00       	jmp    1497 <.altinstr_replacement+0x1497>	1493: R_X86_64_PC32	.text+0x31d906
1497     1497:	48 89 f8             	mov    %rdi,%rax
149a     149a:	e9 00 00 00 00       	jmp    149f <.altinstr_replacement+0x149f>	149b: R_X86_64_PC32	.text+0x31d88d
149f     149f:	e9 00 00 00 00       	jmp    14a4 <.altinstr_replacement+0x14a4>	14a0: R_X86_64_PC32	.text+0x31d8e0
14a4     14a4:	48 89 f8             	mov    %rdi,%rax
14a7     14a7:	e9 00 00 00 00       	jmp    14ac <.altinstr_replacement+0x14ac>	14a8: R_X86_64_PC32	.text+0x31d8b1
14ac     14ac:	e9 00 00 00 00       	jmp    14b1 <.altinstr_replacement+0x14b1>	14ad: R_X86_64_PC32	.text+0x31d8f3
14b1     14b1:	e9 00 00 00 00       	jmp    14b6 <.altinstr_replacement+0x14b6>	14b2: R_X86_64_PC32	.text+0x31db80
14b6     14b6:	48 89 f8             	mov    %rdi,%rax
14b9     14b9:	48 89 f8             	mov    %rdi,%rax
14bc     14bc:	48 89 f8             	mov    %rdi,%rax
14bf     14bf:	48 89 f8             	mov    %rdi,%rax
14c2     14c2:	48 89 f8             	mov    %rdi,%rax
14c5     14c5:	48 89 f8             	mov    %rdi,%rax
14c8     14c8:	48 89 f8             	mov    %rdi,%rax
14cb     14cb:	48 89 f8             	mov    %rdi,%rax
14ce     14ce:	48 89 f8             	mov    %rdi,%rax
14d1     14d1:	48 89 f8             	mov    %rdi,%rax
14d4     14d4:	e9 00 00 00 00       	jmp    14d9 <.altinstr_replacement+0x14d9>	14d5: R_X86_64_PC32	.text+0x31f71e
14d9     14d9:	48 89 f8             	mov    %rdi,%rax
14dc     14dc:	0f 20 d8             	mov    %cr3,%rax
14df     14df:	48 89 f8             	mov    %rdi,%rax
14e2     14e2:	e9 00 00 00 00       	jmp    14e7 <.altinstr_replacement+0x14e7>	14e3: R_X86_64_PC32	.text+0x31f8f4
14e7     14e7:	48 89 f8             	mov    %rdi,%rax
14ea     14ea:	48 89 f8             	mov    %rdi,%rax
14ed     14ed:	48 89 f8             	mov    %rdi,%rax
14f0     14f0:	48 89 f8             	mov    %rdi,%rax
14f3     14f3:	48 89 f8             	mov    %rdi,%rax
14f6     14f6:	48 89 f8             	mov    %rdi,%rax
14f9     14f9:	48 89 f8             	mov    %rdi,%rax
14fc     14fc:	48 89 f8             	mov    %rdi,%rax
14ff     14ff:	0f 20 d8             	mov    %cr3,%rax
1502     1502:	48 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbp
150c     150c:	fb                   	sti
150d     150d:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
1517     1517:	9c                   	pushf
1518     1518:	58                   	pop    %rax
1519     1519:	fa                   	cli
151a     151a:	e9 00 00 00 00       	jmp    151f <.altinstr_replacement+0x151f>	151b: R_X86_64_PC32	.text+0x320d8f
151f     151f:	e9 00 00 00 00       	jmp    1524 <.altinstr_replacement+0x1524>	1520: R_X86_64_PC32	.text+0x320ea8
1524     1524:	9c                   	pushf
1525     1525:	58                   	pop    %rax
1526     1526:	e9 00 00 00 00       	jmp    152b <.altinstr_replacement+0x152b>	1527: R_X86_64_PC32	.text+0x321142
152b     152b:	fb                   	sti
152c     152c:	fb                   	sti
152d     152d:	e9 00 00 00 00       	jmp    1532 <.altinstr_replacement+0x1532>	152e: R_X86_64_PC32	.text+0x321b30
1532     1532:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
153c     153c:	e9 00 00 00 00       	jmp    1541 <.altinstr_replacement+0x1541>	153d: R_X86_64_PC32	.text+0x322041
1541     1541:	48 89 f8             	mov    %rdi,%rax
1544     1544:	48 89 f8             	mov    %rdi,%rax
1547     1547:	48 89 f8             	mov    %rdi,%rax
154a     154a:	48 89 f8             	mov    %rdi,%rax
154d     154d:	9c                   	pushf
154e     154e:	58                   	pop    %rax
154f     154f:	48 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbp
1559     1559:	0f 20 d0             	mov    %cr2,%rax
155c     155c:	0f 0d 88 38 03 00 00 	prefetchw 0x338(%rax)
1563     1563:	9c                   	pushf
1564     1564:	58                   	pop    %rax
1565     1565:	fa                   	cli
1566     1566:	e9 00 00 00 00       	jmp    156b <.altinstr_replacement+0x156b>	1567: R_X86_64_PC32	.text.unlikely+0x2d495
156b     156b:	48 89 f8             	mov    %rdi,%rax
156e     156e:	0f 20 d8             	mov    %cr3,%rax
1571     1571:	48 89 f8             	mov    %rdi,%rax
1574     1574:	48 89 f8             	mov    %rdi,%rax
1577     1577:	e9 00 00 00 00       	jmp    157c <.altinstr_replacement+0x157c>	1578: R_X86_64_PC32	.text+0x3235e9
157c     157c:	e9 00 00 00 00       	jmp    1581 <.altinstr_replacement+0x1581>	157d: R_X86_64_PC32	.text+0x3235f4
1581     1581:	48 89 f8             	mov    %rdi,%rax
1584     1584:	48 89 f8             	mov    %rdi,%rax
1587     1587:	e9 00 00 00 00       	jmp    158c <.altinstr_replacement+0x158c>	1588: R_X86_64_PC32	.text+0x324b09
158c     158c:	0f 20 d0             	mov    %cr2,%rax
158f     158f:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
1599     1599:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
15a3     15a3:	e9 00 00 00 00       	jmp    15a8 <.altinstr_replacement+0x15a8>	15a4: R_X86_64_PC32	.text+0x325b35
15a8     15a8:	e9 00 00 00 00       	jmp    15ad <.altinstr_replacement+0x15ad>	15a9: R_X86_64_PC32	.text+0x3259d6
15ad     15ad:	9c                   	pushf
15ae     15ae:	58                   	pop    %rax
15af     15af:	fa                   	cli
15b0     15b0:	9c                   	pushf
15b1     15b1:	58                   	pop    %rax
15b2     15b2:	fb                   	sti
15b3     15b3:	e9 00 00 00 00       	jmp    15b8 <.altinstr_replacement+0x15b8>	15b4: R_X86_64_PC32	.text+0x325d6f
15b8     15b8:	48 89 f8             	mov    %rdi,%rax
15bb     15bb:	48 89 f8             	mov    %rdi,%rax
15be     15be:	e9 00 00 00 00       	jmp    15c3 <.altinstr_replacement+0x15c3>	15bf: R_X86_64_PC32	.text+0x325ecb
15c3     15c3:	48 89 f8             	mov    %rdi,%rax
15c6     15c6:	48 89 f8             	mov    %rdi,%rax
15c9     15c9:	48 89 f8             	mov    %rdi,%rax
15cc     15cc:	48 89 f8             	mov    %rdi,%rax
15cf     15cf:	48 89 f8             	mov    %rdi,%rax
15d2     15d2:	48 89 f8             	mov    %rdi,%rax
15d5     15d5:	48 89 f8             	mov    %rdi,%rax
15d8     15d8:	48 89 f8             	mov    %rdi,%rax
15db     15db:	48 89 f8             	mov    %rdi,%rax
15de     15de:	48 89 f8             	mov    %rdi,%rax
15e1     15e1:	48 89 f8             	mov    %rdi,%rax
15e4     15e4:	48 89 f8             	mov    %rdi,%rax
15e7     15e7:	48 89 f8             	mov    %rdi,%rax
15ea     15ea:	e9 00 00 00 00       	jmp    15ef <.altinstr_replacement+0x15ef>	15eb: R_X86_64_PC32	.text+0x328be9
15ef     15ef:	e9 00 00 00 00       	jmp    15f4 <.altinstr_replacement+0x15f4>	15f0: R_X86_64_PC32	.text+0x328c72
15f4     15f4:	e9 00 00 00 00       	jmp    15f9 <.altinstr_replacement+0x15f9>	15f5: R_X86_64_PC32	.text+0x3290a4
15f9     15f9:	e9 00 00 00 00       	jmp    15fe <.altinstr_replacement+0x15fe>	15fa: R_X86_64_PC32	.text+0x3290a4
15fe     15fe:	9c                   	pushf
15ff     15ff:	58                   	pop    %rax
1600     1600:	e9 00 00 00 00       	jmp    1605 <.altinstr_replacement+0x1605>	1601: R_X86_64_PC32	.text+0x329705
1605     1605:	0f 22 df             	mov    %rdi,%cr3
1608     1608:	0f 20 d8             	mov    %cr3,%rax
160b     160b:	9c                   	pushf
160c     160c:	58                   	pop    %rax
160d     160d:	9c                   	pushf
160e     160e:	58                   	pop    %rax
160f     160f:	0f 20 d8             	mov    %cr3,%rax
1612     1612:	0f 30                	wrmsr
1614     1614:	e9 00 00 00 00       	jmp    1619 <.altinstr_replacement+0x1619>	1615: R_X86_64_PC32	.text+0x329e93
1619     1619:	0f 30                	wrmsr
161b     161b:	e9 00 00 00 00       	jmp    1620 <.altinstr_replacement+0x1620>	161c: R_X86_64_PC32	.text+0x32a161
1620     1620:	9c                   	pushf
1621     1621:	58                   	pop    %rax
1622     1622:	fa                   	cli
1623     1623:	9c                   	pushf
1624     1624:	58                   	pop    %rax
1625     1625:	fb                   	sti
1626     1626:	9c                   	pushf
1627     1627:	58                   	pop    %rax
1628     1628:	0f 20 d8             	mov    %cr3,%rax
162b     162b:	0f 22 df             	mov    %rdi,%cr3
162e     162e:	9c                   	pushf
162f     162f:	58                   	pop    %rax
1630     1630:	fa                   	cli
1631     1631:	fb                   	sti
1632     1632:	e9 00 00 00 00       	jmp    1637 <.altinstr_replacement+0x1637>	1633: R_X86_64_PC32	.text+0x32affd
1637     1637:	e9 00 00 00 00       	jmp    163c <.altinstr_replacement+0x163c>	1638: R_X86_64_PC32	.text+0x32b163
163c     163c:	e9 00 00 00 00       	jmp    1641 <.altinstr_replacement+0x1641>	163d: R_X86_64_PC32	.text+0x32b2fd
1641     1641:	9c                   	pushf
1642     1642:	58                   	pop    %rax
1643     1643:	fa                   	cli
1644     1644:	9c                   	pushf
1645     1645:	58                   	pop    %rax
1646     1646:	fb                   	sti
1647     1647:	9c                   	pushf
1648     1648:	58                   	pop    %rax
1649     1649:	9c                   	pushf
164a     164a:	58                   	pop    %rax
164b     164b:	fa                   	cli
164c     164c:	fb                   	sti
164d     164d:	0f 20 d8             	mov    %cr3,%rax
1650     1650:	48 89 f8             	mov    %rdi,%rax
1653     1653:	48 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbp
165d     165d:	e9 00 00 00 00       	jmp    1662 <.altinstr_replacement+0x1662>	165e: R_X86_64_PC32	.text+0x32bf1e
1662     1662:	48 89 f8             	mov    %rdi,%rax
1665     1665:	48 89 f8             	mov    %rdi,%rax
1668     1668:	0f 09                	wbinvd
166a     166a:	48 89 f8             	mov    %rdi,%rax
166d     166d:	e9 00 00 00 00       	jmp    1672 <.altinstr_replacement+0x1672>	166e: R_X86_64_PC32	.text+0x32c5b1
1672     1672:	9c                   	pushf
1673     1673:	58                   	pop    %rax
1674     1674:	66 0f ae 3b          	clflushopt (%rbx)
1678     1678:	66 0f ae 3b          	clflushopt (%rbx)
167c     167c:	48 89 f8             	mov    %rdi,%rax
167f     167f:	48 89 f8             	mov    %rdi,%rax
1682     1682:	48 89 f8             	mov    %rdi,%rax
1685     1685:	48 89 f8             	mov    %rdi,%rax
1688     1688:	48 89 f8             	mov    %rdi,%rax
168b     168b:	48 89 f8             	mov    %rdi,%rax
168e     168e:	48 89 f8             	mov    %rdi,%rax
1691     1691:	48 89 f8             	mov    %rdi,%rax
1694     1694:	48 89 f8             	mov    %rdi,%rax
1697     1697:	48 89 f8             	mov    %rdi,%rax
169a     169a:	48 89 f8             	mov    %rdi,%rax
169d     169d:	48 89 f8             	mov    %rdi,%rax
16a0     16a0:	48 89 f8             	mov    %rdi,%rax
16a3     16a3:	48 89 f8             	mov    %rdi,%rax
16a6     16a6:	48 89 f8             	mov    %rdi,%rax
16a9     16a9:	48 89 f8             	mov    %rdi,%rax
16ac     16ac:	48 89 f8             	mov    %rdi,%rax
16af     16af:	48 89 f8             	mov    %rdi,%rax
16b2     16b2:	48 89 f8             	mov    %rdi,%rax
16b5     16b5:	e9 00 00 00 00       	jmp    16ba <.altinstr_replacement+0x16ba>	16b6: R_X86_64_PC32	.text+0x32eb54
16ba     16ba:	e9 00 00 00 00       	jmp    16bf <.altinstr_replacement+0x16bf>	16bb: R_X86_64_PC32	.text+0x32ecbc
16bf     16bf:	48 89 f8             	mov    %rdi,%rax
16c2     16c2:	48 89 f8             	mov    %rdi,%rax
16c5     16c5:	48 89 f8             	mov    %rdi,%rax
16c8     16c8:	48 89 f8             	mov    %rdi,%rax
16cb     16cb:	48 89 f8             	mov    %rdi,%rax
16ce     16ce:	e9 00 00 00 00       	jmp    16d3 <.altinstr_replacement+0x16d3>	16cf: R_X86_64_PC32	.text+0x32f371
16d3     16d3:	48 89 f8             	mov    %rdi,%rax
16d6     16d6:	48 89 f8             	mov    %rdi,%rax
16d9     16d9:	48 89 f8             	mov    %rdi,%rax
16dc     16dc:	48 89 f8             	mov    %rdi,%rax
16df     16df:	48 89 f8             	mov    %rdi,%rax
16e2     16e2:	48 89 f8             	mov    %rdi,%rax
16e5     16e5:	48 89 f8             	mov    %rdi,%rax
16e8     16e8:	9c                   	pushf
16e9     16e9:	58                   	pop    %rax
16ea     16ea:	e9 00 00 00 00       	jmp    16ef <.altinstr_replacement+0x16ef>	16eb: R_X86_64_PC32	.text+0x330135
16ef     16ef:	48 89 f8             	mov    %rdi,%rax
16f2     16f2:	66 41 0f ae 7d 00    	clflushopt 0x0(%r13)
16f8     16f8:	48 89 f8             	mov    %rdi,%rax
16fb     16fb:	48 89 f8             	mov    %rdi,%rax
16fe     16fe:	48 89 f8             	mov    %rdi,%rax
1701     1701:	48 89 f8             	mov    %rdi,%rax
1704     1704:	48 89 f8             	mov    %rdi,%rax
1707     1707:	48 89 f8             	mov    %rdi,%rax
170a     170a:	48 89 f8             	mov    %rdi,%rax
170d     170d:	48 89 f8             	mov    %rdi,%rax
1710     1710:	48 89 f8             	mov    %rdi,%rax
1713     1713:	48 89 f8             	mov    %rdi,%rax
1716     1716:	48 89 f8             	mov    %rdi,%rax
1719     1719:	48 89 f8             	mov    %rdi,%rax
171c     171c:	48 89 f8             	mov    %rdi,%rax
171f     171f:	48 89 f8             	mov    %rdi,%rax
1722     1722:	48 89 f8             	mov    %rdi,%rax
1725     1725:	e9 00 00 00 00       	jmp    172a <.altinstr_replacement+0x172a>	1726: R_X86_64_PC32	.text+0x3352eb
172a     172a:	48 89 f8             	mov    %rdi,%rax
172d     172d:	48 89 f8             	mov    %rdi,%rax
1730     1730:	48 89 f8             	mov    %rdi,%rax
1733     1733:	48 89 f8             	mov    %rdi,%rax
1736     1736:	e9 00 00 00 00       	jmp    173b <.altinstr_replacement+0x173b>	1737: R_X86_64_PC32	.init.text+0x82ff4
173b     173b:	48 ba 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rdx
1745     1745:	48 89 f8             	mov    %rdi,%rax
1748     1748:	48 89 f8             	mov    %rdi,%rax
174b     174b:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
1755     1755:	e9 00 00 00 00       	jmp    175a <.altinstr_replacement+0x175a>	1756: R_X86_64_PC32	.init.text+0x8331c
175a     175a:	e9 00 00 00 00       	jmp    175f <.altinstr_replacement+0x175f>	175b: R_X86_64_PC32	.init.text+0x8337c
175f     175f:	e9 00 00 00 00       	jmp    1764 <.altinstr_replacement+0x1764>	1760: R_X86_64_PC32	.init.text+0x833b2
1764     1764:	48 89 f8             	mov    %rdi,%rax
1767     1767:	48 89 f8             	mov    %rdi,%rax
176a     176a:	48 89 f8             	mov    %rdi,%rax
176d     176d:	48 89 f8             	mov    %rdi,%rax
1770     1770:	48 89 f8             	mov    %rdi,%rax
1773     1773:	48 89 f8             	mov    %rdi,%rax
1776     1776:	48 89 f8             	mov    %rdi,%rax
1779     1779:	0f 22 df             	mov    %rdi,%cr3
177c     177c:	48 89 f8             	mov    %rdi,%rax
177f     177f:	48 89 f8             	mov    %rdi,%rax
1782     1782:	48 89 f8             	mov    %rdi,%rax
1785     1785:	48 89 f8             	mov    %rdi,%rax
1788     1788:	48 89 f8             	mov    %rdi,%rax
178b     178b:	48 89 f8             	mov    %rdi,%rax
178e     178e:	48 89 f8             	mov    %rdi,%rax
1791     1791:	48 89 f8             	mov    %rdi,%rax
1794     1794:	48 89 f8             	mov    %rdi,%rax
1797     1797:	e9 00 00 00 00       	jmp    179c <.altinstr_replacement+0x179c>	1798: R_X86_64_PC32	.init.text+0x8c7ca
179c     179c:	e9 00 00 00 00       	jmp    17a1 <.altinstr_replacement+0x17a1>	179d: R_X86_64_PC32	.text+0x3426e2
17a1     17a1:	e9 00 00 00 00       	jmp    17a6 <.altinstr_replacement+0x17a6>	17a2: R_X86_64_PC32	.text+0x342778
17a6     17a6:	e9 00 00 00 00       	jmp    17ab <.altinstr_replacement+0x17ab>	17a7: R_X86_64_PC32	.text+0x3429df
17ab     17ab:	e9 00 00 00 00       	jmp    17b0 <.altinstr_replacement+0x17b0>	17ac: R_X86_64_PC32	.text+0x342c5e
17b0     17b0:	48 89 f8             	mov    %rdi,%rax
17b3     17b3:	48 89 f8             	mov    %rdi,%rax
17b6     17b6:	e9 00 00 00 00       	jmp    17bb <.altinstr_replacement+0x17bb>	17b7: R_X86_64_PC32	.text+0x342dee
17bb     17bb:	e9 00 00 00 00       	jmp    17c0 <.altinstr_replacement+0x17c0>	17bc: R_X86_64_PC32	.text+0x342e81
17c0     17c0:	48 89 f8             	mov    %rdi,%rax
17c3     17c3:	48 89 f8             	mov    %rdi,%rax
17c6     17c6:	48 89 f8             	mov    %rdi,%rax
17c9     17c9:	48 89 f8             	mov    %rdi,%rax
17cc     17cc:	48 89 f8             	mov    %rdi,%rax
17cf     17cf:	48 89 f8             	mov    %rdi,%rax
17d2     17d2:	48 89 f8             	mov    %rdi,%rax
17d5     17d5:	48 89 f8             	mov    %rdi,%rax
17d8     17d8:	48 89 f8             	mov    %rdi,%rax
17db     17db:	e9 00 00 00 00       	jmp    17e0 <.altinstr_replacement+0x17e0>	17dc: R_X86_64_PC32	.text+0x3433f4
17e0     17e0:	48 89 f8             	mov    %rdi,%rax
17e3     17e3:	48 89 f8             	mov    %rdi,%rax
17e6     17e6:	e9 00 00 00 00       	jmp    17eb <.altinstr_replacement+0x17eb>	17e7: R_X86_64_PC32	.text+0x343925
17eb     17eb:	e9 00 00 00 00       	jmp    17f0 <.altinstr_replacement+0x17f0>	17ec: R_X86_64_PC32	.text.unlikely+0x30233
17f0     17f0:	e9 00 00 00 00       	jmp    17f5 <.altinstr_replacement+0x17f5>	17f1: R_X86_64_PC32	.text+0x343a8c
17f5     17f5:	0f 09                	wbinvd
17f7     17f7:	48 89 f8             	mov    %rdi,%rax
17fa     17fa:	48 89 f8             	mov    %rdi,%rax
17fd     17fd:	48 89 f8             	mov    %rdi,%rax
1800     1800:	48 89 f8             	mov    %rdi,%rax
1803     1803:	e9 00 00 00 00       	jmp    1808 <.altinstr_replacement+0x1808>	1804: R_X86_64_PC32	.text.unlikely+0x3047e
1808     1808:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
1812     1812:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
181c     181c:	49 be 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r14
1826     1826:	0f 01 cb             	stac
1829     1829:	0f ae e8             	lfence
182c     182c:	0f 01 ca             	clac
182f     182f:	0f 01 ca             	clac
1832     1832:	49 be 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r14
183c     183c:	0f 01 cb             	stac
183f     183f:	0f ae e8             	lfence
1842     1842:	e9 00 00 00 00       	jmp    1847 <.altinstr_replacement+0x1847>	1843: R_X86_64_PC32	.text+0x415d4b
1847     1847:	0f 01 ca             	clac
184a     184a:	0f 01 ca             	clac
184d     184d:	0f 30                	wrmsr
184f     184f:	48 89 f8             	mov    %rdi,%rax
1852     1852:	e9 00 00 00 00       	jmp    1857 <.altinstr_replacement+0x1857>	1853: R_X86_64_PC32	.text+0x4170e6
1857     1857:	48 89 f8             	mov    %rdi,%rax
185a     185a:	e9 00 00 00 00       	jmp    185f <.altinstr_replacement+0x185f>	185b: R_X86_64_PC32	.init.text+0x96521
185f     185f:	e9 00 00 00 00       	jmp    1864 <.altinstr_replacement+0x1864>	1860: R_X86_64_PC32	.init.text+0x96632
1864     1864:	48 89 f8             	mov    %rdi,%rax
1867     1867:	e9 00 00 00 00       	jmp    186c <.altinstr_replacement+0x186c>	1868: R_X86_64_PC32	.init.text+0x96728
186c     186c:	48 89 f8             	mov    %rdi,%rax
186f     186f:	48 89 f8             	mov    %rdi,%rax
1872     1872:	48 89 f8             	mov    %rdi,%rax
1875     1875:	48 89 f8             	mov    %rdi,%rax
1878     1878:	9c                   	pushf
1879     1879:	58                   	pop    %rax
187a     187a:	fa                   	cli
187b     187b:	9c                   	pushf
187c     187c:	58                   	pop    %rax
187d     187d:	fb                   	sti
187e     187e:	0f 30                	wrmsr
1880     1880:	0f 30                	wrmsr
1882     1882:	0f 30                	wrmsr
1884     1884:	0f 30                	wrmsr
1886     1886:	0f 30                	wrmsr
1888     1888:	0f 30                	wrmsr
188a     188a:	0f 30                	wrmsr
188c     188c:	0f 30                	wrmsr
188e     188e:	0f 30                	wrmsr
1890     1890:	9c                   	pushf
1891     1891:	58                   	pop    %rax
1892     1892:	fa                   	cli
1893     1893:	9c                   	pushf
1894     1894:	58                   	pop    %rax
1895     1895:	fb                   	sti
1896     1896:	0f 30                	wrmsr
1898     1898:	0f 30                	wrmsr
189a     189a:	0f 30                	wrmsr
189c     189c:	0f 30                	wrmsr
189e     189e:	0f 30                	wrmsr
18a0     18a0:	0f 30                	wrmsr
18a2     18a2:	0f 30                	wrmsr
18a4     18a4:	0f 30                	wrmsr
18a6     18a6:	0f 30                	wrmsr
18a8     18a8:	0f 30                	wrmsr
18aa     18aa:	0f 30                	wrmsr
18ac     18ac:	0f 30                	wrmsr
18ae     18ae:	9c                   	pushf
18af     18af:	58                   	pop    %rax
18b0     18b0:	fa                   	cli
18b1     18b1:	9c                   	pushf
18b2     18b2:	58                   	pop    %rax
18b3     18b3:	fb                   	sti
18b4     18b4:	9c                   	pushf
18b5     18b5:	58                   	pop    %rax
18b6     18b6:	fa                   	cli
18b7     18b7:	9c                   	pushf
18b8     18b8:	58                   	pop    %rax
18b9     18b9:	fb                   	sti
18ba     18ba:	0f 30                	wrmsr
18bc     18bc:	0f 30                	wrmsr
18be     18be:	0f 30                	wrmsr
18c0     18c0:	9c                   	pushf
18c1     18c1:	58                   	pop    %rax
18c2     18c2:	fa                   	cli
18c3     18c3:	9c                   	pushf
18c4     18c4:	58                   	pop    %rax
18c5     18c5:	fb                   	sti
18c6     18c6:	9c                   	pushf
18c7     18c7:	58                   	pop    %rax
18c8     18c8:	fa                   	cli
18c9     18c9:	9c                   	pushf
18ca     18ca:	58                   	pop    %rax
18cb     18cb:	fb                   	sti
18cc     18cc:	9c                   	pushf
18cd     18cd:	58                   	pop    %rax
18ce     18ce:	fb                   	sti
18cf     18cf:	e9 00 00 00 00       	jmp    18d4 <.altinstr_replacement+0x18d4>	18d0: R_X86_64_PC32	.text+0x4218cf
18d4     18d4:	e9 00 00 00 00       	jmp    18d9 <.altinstr_replacement+0x18d9>	18d5: R_X86_64_PC32	.text+0x4223bf
18d9     18d9:	e9 00 00 00 00       	jmp    18de <.altinstr_replacement+0x18de>	18da: R_X86_64_PC32	.text+0x422427
18de     18de:	48 b9 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rcx
18e8     18e8:	9c                   	pushf
18e9     18e9:	58                   	pop    %rax
18ea     18ea:	fa                   	cli
18eb     18eb:	9c                   	pushf
18ec     18ec:	58                   	pop    %rax
18ed     18ed:	fb                   	sti
18ee     18ee:	e9 00 00 00 00       	jmp    18f3 <.altinstr_replacement+0x18f3>	18ef: R_X86_64_PC32	.text+0x42cd87
18f3     18f3:	e9 00 00 00 00       	jmp    18f8 <.altinstr_replacement+0x18f8>	18f4: R_X86_64_PC32	.text+0x42e357
18f8     18f8:	e9 00 00 00 00       	jmp    18fd <.altinstr_replacement+0x18fd>	18f9: R_X86_64_PC32	.text+0x431211
18fd     18fd:	49 be 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r14
1907     1907:	9c                   	pushf
1908     1908:	58                   	pop    %rax
1909     1909:	fa                   	cli
190a     190a:	fb                   	sti
190b     190b:	9c                   	pushf
190c     190c:	58                   	pop    %rax
190d     190d:	fa                   	cli
190e     190e:	fb                   	sti
190f     190f:	49 be 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r14
1919     1919:	0f 01 cb             	stac
191c     191c:	0f ae e8             	lfence
191f     191f:	0f 01 ca             	clac
1922     1922:	0f 01 ca             	clac
1925     1925:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
192f     192f:	0f 01 cb             	stac
1932     1932:	0f ae e8             	lfence
1935     1935:	0f 01 ca             	clac
1938     1938:	0f 01 ca             	clac
193b     193b:	9c                   	pushf
193c     193c:	58                   	pop    %rax
193d     193d:	fa                   	cli
193e     193e:	fb                   	sti
193f     193f:	9c                   	pushf
1940     1940:	58                   	pop    %rax
1941     1941:	fa                   	cli
1942     1942:	9c                   	pushf
1943     1943:	58                   	pop    %rax
1944     1944:	fa                   	cli
1945     1945:	9c                   	pushf
1946     1946:	58                   	pop    %rax
1947     1947:	fb                   	sti
1948     1948:	fb                   	sti
1949     1949:	9c                   	pushf
194a     194a:	58                   	pop    %rax
194b     194b:	fa                   	cli
194c     194c:	9c                   	pushf
194d     194d:	58                   	pop    %rax
194e     194e:	fa                   	cli
194f     194f:	fb                   	sti
1950     1950:	fb                   	sti
1951     1951:	9c                   	pushf
1952     1952:	58                   	pop    %rax
1953     1953:	fa                   	cli
1954     1954:	9c                   	pushf
1955     1955:	58                   	pop    %rax
1956     1956:	fb                   	sti
1957     1957:	9c                   	pushf
1958     1958:	58                   	pop    %rax
1959     1959:	fa                   	cli
195a     195a:	fb                   	sti
195b     195b:	9c                   	pushf
195c     195c:	58                   	pop    %rax
195d     195d:	fa                   	cli
195e     195e:	fb                   	sti
195f     195f:	9c                   	pushf
1960     1960:	58                   	pop    %rax
1961     1961:	fa                   	cli
1962     1962:	9c                   	pushf
1963     1963:	58                   	pop    %rax
1964     1964:	fa                   	cli
1965     1965:	9c                   	pushf
1966     1966:	58                   	pop    %rax
1967     1967:	fb                   	sti
1968     1968:	9c                   	pushf
1969     1969:	58                   	pop    %rax
196a     196a:	fa                   	cli
196b     196b:	9c                   	pushf
196c     196c:	58                   	pop    %rax
196d     196d:	fb                   	sti
196e     196e:	9c                   	pushf
196f     196f:	58                   	pop    %rax
1970     1970:	fa                   	cli
1971     1971:	fb                   	sti
1972     1972:	e9 00 00 00 00       	jmp    1977 <.altinstr_replacement+0x1977>	1973: R_X86_64_PC32	.text+0x4519da
1977     1977:	e9 00 00 00 00       	jmp    197c <.altinstr_replacement+0x197c>	1978: R_X86_64_PC32	.text+0x451c22
197c     197c:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
1986     1986:	49 bf 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r15
1990     1990:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
199a     199a:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
19a4     19a4:	0f 01 cb             	stac
19a7     19a7:	e8 00 00 00 00       	call   19ac <.altinstr_replacement+0x19ac>	19a8: R_X86_64_PLT32	clear_user_erms-0x4
19ac     19ac:	e8 00 00 00 00       	call   19b1 <.altinstr_replacement+0x19b1>	19ad: R_X86_64_PLT32	clear_user_rep_good-0x4
19b1     19b1:	e8 00 00 00 00       	call   19b6 <.altinstr_replacement+0x19b6>	19b2: R_X86_64_PLT32	clear_user_original-0x4
19b6     19b6:	0f 01 ca             	clac
19b9     19b9:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
19c3     19c3:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
19cd     19cd:	49 be 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r14
19d7     19d7:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
19e1     19e1:	9c                   	pushf
19e2     19e2:	58                   	pop    %rax
19e3     19e3:	fa                   	cli
19e4     19e4:	9c                   	pushf
19e5     19e5:	58                   	pop    %rax
19e6     19e6:	fb                   	sti
19e7     19e7:	9c                   	pushf
19e8     19e8:	58                   	pop    %rax
19e9     19e9:	fa                   	cli
19ea     19ea:	9c                   	pushf
19eb     19eb:	58                   	pop    %rax
19ec     19ec:	fb                   	sti
19ed     19ed:	9c                   	pushf
19ee     19ee:	58                   	pop    %rax
19ef     19ef:	fa                   	cli
19f0     19f0:	fb                   	sti
19f1     19f1:	9c                   	pushf
19f2     19f2:	58                   	pop    %rax
19f3     19f3:	fa                   	cli
19f4     19f4:	9c                   	pushf
19f5     19f5:	58                   	pop    %rax
19f6     19f6:	fb                   	sti
19f7     19f7:	9c                   	pushf
19f8     19f8:	58                   	pop    %rax
19f9     19f9:	fa                   	cli
19fa     19fa:	fb                   	sti
19fb     19fb:	9c                   	pushf
19fc     19fc:	58                   	pop    %rax
19fd     19fd:	fa                   	cli
19fe     19fe:	9c                   	pushf
19ff     19ff:	58                   	pop    %rax
1a00     1a00:	fb                   	sti
1a01     1a01:	9c                   	pushf
1a02     1a02:	58                   	pop    %rax
1a03     1a03:	fb                   	sti
1a04     1a04:	9c                   	pushf
1a05     1a05:	58                   	pop    %rax
1a06     1a06:	fb                   	sti
1a07     1a07:	9c                   	pushf
1a08     1a08:	58                   	pop    %rax
1a09     1a09:	fb                   	sti
1a0a     1a0a:	9c                   	pushf
1a0b     1a0b:	58                   	pop    %rax
1a0c     1a0c:	9c                   	pushf
1a0d     1a0d:	58                   	pop    %rax
1a0e     1a0e:	9c                   	pushf
1a0f     1a0f:	58                   	pop    %rax
1a10     1a10:	fa                   	cli
1a11     1a11:	fb                   	sti
1a12     1a12:	9c                   	pushf
1a13     1a13:	58                   	pop    %rax
1a14     1a14:	fa                   	cli
1a15     1a15:	fb                   	sti
1a16     1a16:	9c                   	pushf
1a17     1a17:	58                   	pop    %rax
1a18     1a18:	fa                   	cli
1a19     1a19:	9c                   	pushf
1a1a     1a1a:	58                   	pop    %rax
1a1b     1a1b:	fb                   	sti
1a1c     1a1c:	e9 00 00 00 00       	jmp    1a21 <.altinstr_replacement+0x1a21>	1a1d: R_X86_64_PC32	.text+0x4c16c8
1a21     1a21:	e9 00 00 00 00       	jmp    1a26 <.altinstr_replacement+0x1a26>	1a22: R_X86_64_PC32	.text+0x4c16d7
1a26     1a26:	9c                   	pushf
1a27     1a27:	58                   	pop    %rax
1a28     1a28:	9c                   	pushf
1a29     1a29:	58                   	pop    %rax
1a2a     1a2a:	9c                   	pushf
1a2b     1a2b:	58                   	pop    %rax
1a2c     1a2c:	9c                   	pushf
1a2d     1a2d:	58                   	pop    %rax
1a2e     1a2e:	9c                   	pushf
1a2f     1a2f:	58                   	pop    %rax
1a30     1a30:	9c                   	pushf
1a31     1a31:	58                   	pop    %rax
1a32     1a32:	9c                   	pushf
1a33     1a33:	58                   	pop    %rax
1a34     1a34:	9c                   	pushf
1a35     1a35:	58                   	pop    %rax
1a36     1a36:	9c                   	pushf
1a37     1a37:	58                   	pop    %rax
1a38     1a38:	fb                   	sti
1a39     1a39:	9c                   	pushf
1a3a     1a3a:	58                   	pop    %rax
1a3b     1a3b:	fa                   	cli
1a3c     1a3c:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
1a46     1a46:	9c                   	pushf
1a47     1a47:	58                   	pop    %rax
1a48     1a48:	fa                   	cli
1a49     1a49:	9c                   	pushf
1a4a     1a4a:	58                   	pop    %rax
1a4b     1a4b:	fa                   	cli
1a4c     1a4c:	9c                   	pushf
1a4d     1a4d:	58                   	pop    %rax
1a4e     1a4e:	fa                   	cli
1a4f     1a4f:	9c                   	pushf
1a50     1a50:	58                   	pop    %rax
1a51     1a51:	fb                   	sti
1a52     1a52:	fb                   	sti
1a53     1a53:	9c                   	pushf
1a54     1a54:	58                   	pop    %rax
1a55     1a55:	fa                   	cli
1a56     1a56:	fb                   	sti
1a57     1a57:	fb                   	sti
1a58     1a58:	9c                   	pushf
1a59     1a59:	58                   	pop    %rax
1a5a     1a5a:	9c                   	pushf
1a5b     1a5b:	58                   	pop    %rax
1a5c     1a5c:	9c                   	pushf
1a5d     1a5d:	58                   	pop    %rax
1a5e     1a5e:	fa                   	cli
1a5f     1a5f:	9c                   	pushf
1a60     1a60:	58                   	pop    %rax
1a61     1a61:	fb                   	sti
1a62     1a62:	fb                   	sti
1a63     1a63:	9c                   	pushf
1a64     1a64:	58                   	pop    %rax
1a65     1a65:	fa                   	cli
1a66     1a66:	9c                   	pushf
1a67     1a67:	58                   	pop    %rax
1a68     1a68:	fa                   	cli
1a69     1a69:	fb                   	sti
1a6a     1a6a:	fb                   	sti
1a6b     1a6b:	9c                   	pushf
1a6c     1a6c:	58                   	pop    %rax
1a6d     1a6d:	fb                   	sti
1a6e     1a6e:	9c                   	pushf
1a6f     1a6f:	58                   	pop    %rax
1a70     1a70:	fa                   	cli
1a71     1a71:	48 31 c0             	xor    %rax,%rax
1a74     1a74:	9c                   	pushf
1a75     1a75:	58                   	pop    %rax
1a76     1a76:	fa                   	cli
1a77     1a77:	9c                   	pushf
1a78     1a78:	58                   	pop    %rax
1a79     1a79:	fa                   	cli
1a7a     1a7a:	9c                   	pushf
1a7b     1a7b:	58                   	pop    %rax
1a7c     1a7c:	fb                   	sti
1a7d     1a7d:	9c                   	pushf
1a7e     1a7e:	58                   	pop    %rax
1a7f     1a7f:	fb                   	sti
1a80     1a80:	9c                   	pushf
1a81     1a81:	58                   	pop    %rax
1a82     1a82:	fb                   	sti
1a83     1a83:	fb                   	sti
1a84     1a84:	9c                   	pushf
1a85     1a85:	58                   	pop    %rax
1a86     1a86:	fa                   	cli
1a87     1a87:	fb                   	sti
1a88     1a88:	9c                   	pushf
1a89     1a89:	58                   	pop    %rax
1a8a     1a8a:	fa                   	cli
1a8b     1a8b:	9c                   	pushf
1a8c     1a8c:	58                   	pop    %rax
1a8d     1a8d:	fb                   	sti
1a8e     1a8e:	fb                   	sti
1a8f     1a8f:	fb                   	sti
1a90     1a90:	fb                   	sti
1a91     1a91:	fb                   	sti
1a92     1a92:	fa                   	cli
1a93     1a93:	fb                   	sti
1a94     1a94:	9c                   	pushf
1a95     1a95:	58                   	pop    %rax
1a96     1a96:	fb                   	sti
1a97     1a97:	9c                   	pushf
1a98     1a98:	58                   	pop    %rax
1a99     1a99:	fa                   	cli
1a9a     1a9a:	e9 00 00 00 00       	jmp    1a9f <.altinstr_replacement+0x1a9f>	1a9b: R_X86_64_PC32	.text+0x527ad7
1a9f     1a9f:	e9 00 00 00 00       	jmp    1aa4 <.altinstr_replacement+0x1aa4>	1aa0: R_X86_64_PC32	.text+0x527ae6
1aa4     1aa4:	9c                   	pushf
1aa5     1aa5:	58                   	pop    %rax
1aa6     1aa6:	fa                   	cli
1aa7     1aa7:	fb                   	sti
1aa8     1aa8:	9c                   	pushf
1aa9     1aa9:	58                   	pop    %rax
1aaa     1aaa:	fa                   	cli
1aab     1aab:	9c                   	pushf
1aac     1aac:	58                   	pop    %rax
1aad     1aad:	fb                   	sti
1aae     1aae:	9c                   	pushf
1aaf     1aaf:	58                   	pop    %rax
1ab0     1ab0:	fa                   	cli
1ab1     1ab1:	9c                   	pushf
1ab2     1ab2:	58                   	pop    %rax
1ab3     1ab3:	fb                   	sti
1ab4     1ab4:	9c                   	pushf
1ab5     1ab5:	58                   	pop    %rax
1ab6     1ab6:	fa                   	cli
1ab7     1ab7:	9c                   	pushf
1ab8     1ab8:	58                   	pop    %rax
1ab9     1ab9:	fa                   	cli
1aba     1aba:	9c                   	pushf
1abb     1abb:	58                   	pop    %rax
1abc     1abc:	fb                   	sti
1abd     1abd:	9c                   	pushf
1abe     1abe:	58                   	pop    %rax
1abf     1abf:	fa                   	cli
1ac0     1ac0:	fb                   	sti
1ac1     1ac1:	9c                   	pushf
1ac2     1ac2:	58                   	pop    %rax
1ac3     1ac3:	fa                   	cli
1ac4     1ac4:	9c                   	pushf
1ac5     1ac5:	58                   	pop    %rax
1ac6     1ac6:	fb                   	sti
1ac7     1ac7:	9c                   	pushf
1ac8     1ac8:	58                   	pop    %rax
1ac9     1ac9:	fa                   	cli
1aca     1aca:	fb                   	sti
1acb     1acb:	fb                   	sti
1acc     1acc:	fb                   	sti
1acd     1acd:	48 31 c0             	xor    %rax,%rax
1ad0     1ad0:	48 31 c0             	xor    %rax,%rax
1ad3     1ad3:	48 31 c0             	xor    %rax,%rax
1ad6     1ad6:	48 31 c0             	xor    %rax,%rax
1ad9     1ad9:	9c                   	pushf
1ada     1ada:	58                   	pop    %rax
1adb     1adb:	9c                   	pushf
1adc     1adc:	58                   	pop    %rax
1add     1add:	9c                   	pushf
1ade     1ade:	58                   	pop    %rax
1adf     1adf:	9c                   	pushf
1ae0     1ae0:	58                   	pop    %rax
1ae1     1ae1:	9c                   	pushf
1ae2     1ae2:	58                   	pop    %rax
1ae3     1ae3:	9c                   	pushf
1ae4     1ae4:	58                   	pop    %rax
1ae5     1ae5:	9c                   	pushf
1ae6     1ae6:	58                   	pop    %rax
1ae7     1ae7:	9c                   	pushf
1ae8     1ae8:	58                   	pop    %rax
1ae9     1ae9:	c6 07 00             	movb   $0x0,(%rdi)
1aec     1aec:	9c                   	pushf
1aed     1aed:	58                   	pop    %rax
1aee     1aee:	9c                   	pushf
1aef     1aef:	58                   	pop    %rax
1af0     1af0:	fa                   	cli
1af1     1af1:	9c                   	pushf
1af2     1af2:	58                   	pop    %rax
1af3     1af3:	fb                   	sti
1af4     1af4:	9c                   	pushf
1af5     1af5:	58                   	pop    %rax
1af6     1af6:	9c                   	pushf
1af7     1af7:	58                   	pop    %rax
1af8     1af8:	9c                   	pushf
1af9     1af9:	58                   	pop    %rax
1afa     1afa:	9c                   	pushf
1afb     1afb:	58                   	pop    %rax
1afc     1afc:	fa                   	cli
1afd     1afd:	9c                   	pushf
1afe     1afe:	58                   	pop    %rax
1aff     1aff:	fb                   	sti
1b00     1b00:	9c                   	pushf
1b01     1b01:	58                   	pop    %rax
1b02     1b02:	fa                   	cli
1b03     1b03:	9c                   	pushf
1b04     1b04:	58                   	pop    %rax
1b05     1b05:	fb                   	sti
1b06     1b06:	9c                   	pushf
1b07     1b07:	58                   	pop    %rax
1b08     1b08:	fa                   	cli
1b09     1b09:	9c                   	pushf
1b0a     1b0a:	58                   	pop    %rax
1b0b     1b0b:	fb                   	sti
1b0c     1b0c:	9c                   	pushf
1b0d     1b0d:	58                   	pop    %rax
1b0e     1b0e:	fa                   	cli
1b0f     1b0f:	9c                   	pushf
1b10     1b10:	58                   	pop    %rax
1b11     1b11:	fb                   	sti
1b12     1b12:	9c                   	pushf
1b13     1b13:	58                   	pop    %rax
1b14     1b14:	fa                   	cli
1b15     1b15:	9c                   	pushf
1b16     1b16:	58                   	pop    %rax
1b17     1b17:	fb                   	sti
1b18     1b18:	9c                   	pushf
1b19     1b19:	58                   	pop    %rax
1b1a     1b1a:	fa                   	cli
1b1b     1b1b:	9c                   	pushf
1b1c     1b1c:	58                   	pop    %rax
1b1d     1b1d:	fb                   	sti
1b1e     1b1e:	9c                   	pushf
1b1f     1b1f:	58                   	pop    %rax
1b20     1b20:	fa                   	cli
1b21     1b21:	9c                   	pushf
1b22     1b22:	58                   	pop    %rax
1b23     1b23:	fb                   	sti
1b24     1b24:	9c                   	pushf
1b25     1b25:	58                   	pop    %rax
1b26     1b26:	9c                   	pushf
1b27     1b27:	58                   	pop    %rax
1b28     1b28:	fa                   	cli
1b29     1b29:	9c                   	pushf
1b2a     1b2a:	58                   	pop    %rax
1b2b     1b2b:	fb                   	sti
1b2c     1b2c:	9c                   	pushf
1b2d     1b2d:	58                   	pop    %rax
1b2e     1b2e:	fa                   	cli
1b2f     1b2f:	9c                   	pushf
1b30     1b30:	58                   	pop    %rax
1b31     1b31:	fb                   	sti
1b32     1b32:	9c                   	pushf
1b33     1b33:	58                   	pop    %rax
1b34     1b34:	9c                   	pushf
1b35     1b35:	58                   	pop    %rax
1b36     1b36:	9c                   	pushf
1b37     1b37:	58                   	pop    %rax
1b38     1b38:	fa                   	cli
1b39     1b39:	9c                   	pushf
1b3a     1b3a:	58                   	pop    %rax
1b3b     1b3b:	fb                   	sti
1b3c     1b3c:	9c                   	pushf
1b3d     1b3d:	58                   	pop    %rax
1b3e     1b3e:	9c                   	pushf
1b3f     1b3f:	58                   	pop    %rax
1b40     1b40:	9c                   	pushf
1b41     1b41:	58                   	pop    %rax
1b42     1b42:	9c                   	pushf
1b43     1b43:	58                   	pop    %rax
1b44     1b44:	fa                   	cli
1b45     1b45:	9c                   	pushf
1b46     1b46:	58                   	pop    %rax
1b47     1b47:	fb                   	sti
1b48     1b48:	9c                   	pushf
1b49     1b49:	58                   	pop    %rax
1b4a     1b4a:	fa                   	cli
1b4b     1b4b:	9c                   	pushf
1b4c     1b4c:	58                   	pop    %rax
1b4d     1b4d:	fb                   	sti
1b4e     1b4e:	9c                   	pushf
1b4f     1b4f:	58                   	pop    %rax
1b50     1b50:	fa                   	cli
1b51     1b51:	9c                   	pushf
1b52     1b52:	58                   	pop    %rax
1b53     1b53:	fb                   	sti
1b54     1b54:	9c                   	pushf
1b55     1b55:	58                   	pop    %rax
1b56     1b56:	fa                   	cli
1b57     1b57:	9c                   	pushf
1b58     1b58:	58                   	pop    %rax
1b59     1b59:	fb                   	sti
1b5a     1b5a:	9c                   	pushf
1b5b     1b5b:	58                   	pop    %rax
1b5c     1b5c:	fa                   	cli
1b5d     1b5d:	9c                   	pushf
1b5e     1b5e:	58                   	pop    %rax
1b5f     1b5f:	fb                   	sti
1b60     1b60:	9c                   	pushf
1b61     1b61:	58                   	pop    %rax
1b62     1b62:	fa                   	cli
1b63     1b63:	9c                   	pushf
1b64     1b64:	58                   	pop    %rax
1b65     1b65:	fb                   	sti
1b66     1b66:	9c                   	pushf
1b67     1b67:	58                   	pop    %rax
1b68     1b68:	fa                   	cli
1b69     1b69:	9c                   	pushf
1b6a     1b6a:	58                   	pop    %rax
1b6b     1b6b:	fb                   	sti
1b6c     1b6c:	9c                   	pushf
1b6d     1b6d:	58                   	pop    %rax
1b6e     1b6e:	fa                   	cli
1b6f     1b6f:	9c                   	pushf
1b70     1b70:	58                   	pop    %rax
1b71     1b71:	fb                   	sti
1b72     1b72:	9c                   	pushf
1b73     1b73:	58                   	pop    %rax
1b74     1b74:	fa                   	cli
1b75     1b75:	9c                   	pushf
1b76     1b76:	58                   	pop    %rax
1b77     1b77:	fb                   	sti
1b78     1b78:	9c                   	pushf
1b79     1b79:	58                   	pop    %rax
1b7a     1b7a:	fa                   	cli
1b7b     1b7b:	9c                   	pushf
1b7c     1b7c:	58                   	pop    %rax
1b7d     1b7d:	fb                   	sti
1b7e     1b7e:	9c                   	pushf
1b7f     1b7f:	58                   	pop    %rax
1b80     1b80:	9c                   	pushf
1b81     1b81:	58                   	pop    %rax
1b82     1b82:	9c                   	pushf
1b83     1b83:	58                   	pop    %rax
1b84     1b84:	9c                   	pushf
1b85     1b85:	58                   	pop    %rax
1b86     1b86:	9c                   	pushf
1b87     1b87:	58                   	pop    %rax
1b88     1b88:	9c                   	pushf
1b89     1b89:	58                   	pop    %rax
1b8a     1b8a:	9c                   	pushf
1b8b     1b8b:	58                   	pop    %rax
1b8c     1b8c:	fa                   	cli
1b8d     1b8d:	9c                   	pushf
1b8e     1b8e:	58                   	pop    %rax
1b8f     1b8f:	fb                   	sti
1b90     1b90:	9c                   	pushf
1b91     1b91:	58                   	pop    %rax
1b92     1b92:	fa                   	cli
1b93     1b93:	9c                   	pushf
1b94     1b94:	58                   	pop    %rax
1b95     1b95:	fa                   	cli
1b96     1b96:	9c                   	pushf
1b97     1b97:	58                   	pop    %rax
1b98     1b98:	fa                   	cli
1b99     1b99:	fb                   	sti
1b9a     1b9a:	9c                   	pushf
1b9b     1b9b:	58                   	pop    %rax
1b9c     1b9c:	fb                   	sti
1b9d     1b9d:	9c                   	pushf
1b9e     1b9e:	58                   	pop    %rax
1b9f     1b9f:	fa                   	cli
1ba0     1ba0:	9c                   	pushf
1ba1     1ba1:	58                   	pop    %rax
1ba2     1ba2:	fa                   	cli
1ba3     1ba3:	9c                   	pushf
1ba4     1ba4:	58                   	pop    %rax
1ba5     1ba5:	fa                   	cli
1ba6     1ba6:	9c                   	pushf
1ba7     1ba7:	58                   	pop    %rax
1ba8     1ba8:	fa                   	cli
1ba9     1ba9:	fb                   	sti
1baa     1baa:	9c                   	pushf
1bab     1bab:	58                   	pop    %rax
1bac     1bac:	fb                   	sti
1bad     1bad:	fb                   	sti
1bae     1bae:	9c                   	pushf
1baf     1baf:	58                   	pop    %rax
1bb0     1bb0:	fb                   	sti
1bb1     1bb1:	48 31 c0             	xor    %rax,%rax
1bb4     1bb4:	41 0f 0d 0e          	prefetchw (%r14)
1bb8     1bb8:	41 0f 0d 4d 00       	prefetchw 0x0(%r13)
1bbd     1bbd:	48 31 c0             	xor    %rax,%rax
1bc0     1bc0:	c6 07 00             	movb   $0x0,(%rdi)
1bc3     1bc3:	c6 07 00             	movb   $0x0,(%rdi)
1bc6     1bc6:	c6 07 00             	movb   $0x0,(%rdi)
1bc9     1bc9:	9c                   	pushf
1bca     1bca:	58                   	pop    %rax
1bcb     1bcb:	fa                   	cli
1bcc     1bcc:	fb                   	sti
1bcd     1bcd:	9c                   	pushf
1bce     1bce:	58                   	pop    %rax
1bcf     1bcf:	9c                   	pushf
1bd0     1bd0:	58                   	pop    %rax
1bd1     1bd1:	9c                   	pushf
1bd2     1bd2:	58                   	pop    %rax
1bd3     1bd3:	fa                   	cli
1bd4     1bd4:	fb                   	sti
1bd5     1bd5:	9c                   	pushf
1bd6     1bd6:	58                   	pop    %rax
1bd7     1bd7:	fa                   	cli
1bd8     1bd8:	fb                   	sti
1bd9     1bd9:	9c                   	pushf
1bda     1bda:	58                   	pop    %rax
1bdb     1bdb:	fa                   	cli
1bdc     1bdc:	fb                   	sti
1bdd     1bdd:	e9 00 00 00 00       	jmp    1be2 <.altinstr_replacement+0x1be2>	1bde: R_X86_64_PC32	.text.unlikely+0x43f79
1be2     1be2:	e9 00 00 00 00       	jmp    1be7 <.altinstr_replacement+0x1be7>	1be3: R_X86_64_PC32	.text.unlikely+0x43fbd
1be7     1be7:	e9 00 00 00 00       	jmp    1bec <.altinstr_replacement+0x1bec>	1be8: R_X86_64_PC32	.text+0x56fe69
1bec     1bec:	e9 00 00 00 00       	jmp    1bf1 <.altinstr_replacement+0x1bf1>	1bed: R_X86_64_PC32	.text+0x56fe74
1bf1     1bf1:	e9 00 00 00 00       	jmp    1bf6 <.altinstr_replacement+0x1bf6>	1bf2: R_X86_64_PC32	.text+0x57021c
1bf6     1bf6:	e9 00 00 00 00       	jmp    1bfb <.altinstr_replacement+0x1bfb>	1bf7: R_X86_64_PC32	.text+0x57023b
1bfb     1bfb:	e8 00 00 00 00       	call   1c00 <.altinstr_replacement+0x1c00>	1bfc: R_X86_64_PLT32	clear_page_rep-0x4
1c00     1c00:	e8 00 00 00 00       	call   1c05 <.altinstr_replacement+0x1c05>	1c01: R_X86_64_PLT32	clear_page_erms-0x4
1c05     1c05:	e9 00 00 00 00       	jmp    1c0a <.altinstr_replacement+0x1c0a>	1c06: R_X86_64_PC32	.text+0x5706b6
1c0a     1c0a:	e9 00 00 00 00       	jmp    1c0f <.altinstr_replacement+0x1c0f>	1c0b: R_X86_64_PC32	.text+0x5706c1
1c0f     1c0f:	e8 00 00 00 00       	call   1c14 <.altinstr_replacement+0x1c14>	1c10: R_X86_64_PLT32	clear_page_rep-0x4
1c14     1c14:	e8 00 00 00 00       	call   1c19 <.altinstr_replacement+0x1c19>	1c15: R_X86_64_PLT32	clear_page_erms-0x4
1c19     1c19:	e9 00 00 00 00       	jmp    1c1e <.altinstr_replacement+0x1c1e>	1c1a: R_X86_64_PC32	.text+0x57149f
1c1e     1c1e:	e9 00 00 00 00       	jmp    1c23 <.altinstr_replacement+0x1c23>	1c1f: R_X86_64_PC32	.text+0x5714aa
1c23     1c23:	e8 00 00 00 00       	call   1c28 <.altinstr_replacement+0x1c28>	1c24: R_X86_64_PLT32	clear_page_rep-0x4
1c28     1c28:	e8 00 00 00 00       	call   1c2d <.altinstr_replacement+0x1c2d>	1c29: R_X86_64_PLT32	clear_page_erms-0x4
1c2d     1c2d:	e8 00 00 00 00       	call   1c32 <.altinstr_replacement+0x1c32>	1c2e: R_X86_64_PLT32	clear_page_rep-0x4
1c32     1c32:	e8 00 00 00 00       	call   1c37 <.altinstr_replacement+0x1c37>	1c33: R_X86_64_PLT32	clear_page_erms-0x4
1c37     1c37:	9c                   	pushf
1c38     1c38:	58                   	pop    %rax
1c39     1c39:	fa                   	cli
1c3a     1c3a:	9c                   	pushf
1c3b     1c3b:	58                   	pop    %rax
1c3c     1c3c:	fb                   	sti
1c3d     1c3d:	9c                   	pushf
1c3e     1c3e:	58                   	pop    %rax
1c3f     1c3f:	fa                   	cli
1c40     1c40:	9c                   	pushf
1c41     1c41:	58                   	pop    %rax
1c42     1c42:	fb                   	sti
1c43     1c43:	9c                   	pushf
1c44     1c44:	58                   	pop    %rax
1c45     1c45:	fa                   	cli
1c46     1c46:	9c                   	pushf
1c47     1c47:	58                   	pop    %rax
1c48     1c48:	fb                   	sti
1c49     1c49:	9c                   	pushf
1c4a     1c4a:	58                   	pop    %rax
1c4b     1c4b:	fa                   	cli
1c4c     1c4c:	9c                   	pushf
1c4d     1c4d:	58                   	pop    %rax
1c4e     1c4e:	fb                   	sti
1c4f     1c4f:	9c                   	pushf
1c50     1c50:	58                   	pop    %rax
1c51     1c51:	fb                   	sti
1c52     1c52:	9c                   	pushf
1c53     1c53:	58                   	pop    %rax
1c54     1c54:	fa                   	cli
1c55     1c55:	9c                   	pushf
1c56     1c56:	58                   	pop    %rax
1c57     1c57:	fb                   	sti
1c58     1c58:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
1c62     1c62:	49 be 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r14
1c6c     1c6c:	9c                   	pushf
1c6d     1c6d:	58                   	pop    %rax
1c6e     1c6e:	fa                   	cli
1c6f     1c6f:	9c                   	pushf
1c70     1c70:	58                   	pop    %rax
1c71     1c71:	fb                   	sti
1c72     1c72:	9c                   	pushf
1c73     1c73:	58                   	pop    %rax
1c74     1c74:	fb                   	sti
1c75     1c75:	9c                   	pushf
1c76     1c76:	58                   	pop    %rax
1c77     1c77:	fb                   	sti
1c78     1c78:	9c                   	pushf
1c79     1c79:	58                   	pop    %rax
1c7a     1c7a:	fa                   	cli
1c7b     1c7b:	9c                   	pushf
1c7c     1c7c:	58                   	pop    %rax
1c7d     1c7d:	fb                   	sti
1c7e     1c7e:	9c                   	pushf
1c7f     1c7f:	58                   	pop    %rax
1c80     1c80:	fa                   	cli
1c81     1c81:	9c                   	pushf
1c82     1c82:	58                   	pop    %rax
1c83     1c83:	fb                   	sti
1c84     1c84:	9c                   	pushf
1c85     1c85:	58                   	pop    %rax
1c86     1c86:	fa                   	cli
1c87     1c87:	9c                   	pushf
1c88     1c88:	58                   	pop    %rax
1c89     1c89:	fb                   	sti
1c8a     1c8a:	9c                   	pushf
1c8b     1c8b:	58                   	pop    %rax
1c8c     1c8c:	9c                   	pushf
1c8d     1c8d:	58                   	pop    %rax
1c8e     1c8e:	fa                   	cli
1c8f     1c8f:	9c                   	pushf
1c90     1c90:	58                   	pop    %rax
1c91     1c91:	fa                   	cli
1c92     1c92:	fb                   	sti
1c93     1c93:	9c                   	pushf
1c94     1c94:	58                   	pop    %rax
1c95     1c95:	9c                   	pushf
1c96     1c96:	58                   	pop    %rax
1c97     1c97:	9c                   	pushf
1c98     1c98:	58                   	pop    %rax
1c99     1c99:	fa                   	cli
1c9a     1c9a:	9c                   	pushf
1c9b     1c9b:	58                   	pop    %rax
1c9c     1c9c:	fb                   	sti
1c9d     1c9d:	fb                   	sti
1c9e     1c9e:	9c                   	pushf
1c9f     1c9f:	58                   	pop    %rax
1ca0     1ca0:	fa                   	cli
1ca1     1ca1:	9c                   	pushf
1ca2     1ca2:	58                   	pop    %rax
1ca3     1ca3:	fa                   	cli
1ca4     1ca4:	fb                   	sti
1ca5     1ca5:	9c                   	pushf
1ca6     1ca6:	58                   	pop    %rax
1ca7     1ca7:	9c                   	pushf
1ca8     1ca8:	58                   	pop    %rax
1ca9     1ca9:	fa                   	cli
1caa     1caa:	9c                   	pushf
1cab     1cab:	58                   	pop    %rax
1cac     1cac:	9c                   	pushf
1cad     1cad:	58                   	pop    %rax
1cae     1cae:	9c                   	pushf
1caf     1caf:	58                   	pop    %rax
1cb0     1cb0:	fa                   	cli
1cb1     1cb1:	9c                   	pushf
1cb2     1cb2:	58                   	pop    %rax
1cb3     1cb3:	fa                   	cli
1cb4     1cb4:	9c                   	pushf
1cb5     1cb5:	58                   	pop    %rax
1cb6     1cb6:	fb                   	sti
1cb7     1cb7:	9c                   	pushf
1cb8     1cb8:	58                   	pop    %rax
1cb9     1cb9:	fa                   	cli
1cba     1cba:	9c                   	pushf
1cbb     1cbb:	58                   	pop    %rax
1cbc     1cbc:	fb                   	sti
1cbd     1cbd:	9c                   	pushf
1cbe     1cbe:	58                   	pop    %rax
1cbf     1cbf:	fa                   	cli
1cc0     1cc0:	fb                   	sti
1cc1     1cc1:	9c                   	pushf
1cc2     1cc2:	58                   	pop    %rax
1cc3     1cc3:	fa                   	cli
1cc4     1cc4:	fb                   	sti
1cc5     1cc5:	9c                   	pushf
1cc6     1cc6:	58                   	pop    %rax
1cc7     1cc7:	fa                   	cli
1cc8     1cc8:	fb                   	sti
1cc9     1cc9:	9c                   	pushf
1cca     1cca:	58                   	pop    %rax
1ccb     1ccb:	fa                   	cli
1ccc     1ccc:	9c                   	pushf
1ccd     1ccd:	58                   	pop    %rax
1cce     1cce:	fb                   	sti
1ccf     1ccf:	9c                   	pushf
1cd0     1cd0:	58                   	pop    %rax
1cd1     1cd1:	fa                   	cli
1cd2     1cd2:	9c                   	pushf
1cd3     1cd3:	58                   	pop    %rax
1cd4     1cd4:	fb                   	sti
1cd5     1cd5:	9c                   	pushf
1cd6     1cd6:	58                   	pop    %rax
1cd7     1cd7:	fa                   	cli
1cd8     1cd8:	9c                   	pushf
1cd9     1cd9:	58                   	pop    %rax
1cda     1cda:	fa                   	cli
1cdb     1cdb:	9c                   	pushf
1cdc     1cdc:	58                   	pop    %rax
1cdd     1cdd:	fb                   	sti
1cde     1cde:	9c                   	pushf
1cdf     1cdf:	58                   	pop    %rax
1ce0     1ce0:	9c                   	pushf
1ce1     1ce1:	58                   	pop    %rax
1ce2     1ce2:	fb                   	sti
1ce3     1ce3:	9c                   	pushf
1ce4     1ce4:	58                   	pop    %rax
1ce5     1ce5:	fa                   	cli
1ce6     1ce6:	9c                   	pushf
1ce7     1ce7:	58                   	pop    %rax
1ce8     1ce8:	fa                   	cli
1ce9     1ce9:	9c                   	pushf
1cea     1cea:	58                   	pop    %rax
1ceb     1ceb:	9c                   	pushf
1cec     1cec:	58                   	pop    %rax
1ced     1ced:	9c                   	pushf
1cee     1cee:	58                   	pop    %rax
1cef     1cef:	fb                   	sti
1cf0     1cf0:	9c                   	pushf
1cf1     1cf1:	58                   	pop    %rax
1cf2     1cf2:	9c                   	pushf
1cf3     1cf3:	58                   	pop    %rax
1cf4     1cf4:	fa                   	cli
1cf5     1cf5:	9c                   	pushf
1cf6     1cf6:	58                   	pop    %rax
1cf7     1cf7:	fa                   	cli
1cf8     1cf8:	9c                   	pushf
1cf9     1cf9:	58                   	pop    %rax
1cfa     1cfa:	fb                   	sti
1cfb     1cfb:	9c                   	pushf
1cfc     1cfc:	58                   	pop    %rax
1cfd     1cfd:	fa                   	cli
1cfe     1cfe:	9c                   	pushf
1cff     1cff:	58                   	pop    %rax
1d00     1d00:	fa                   	cli
1d01     1d01:	9c                   	pushf
1d02     1d02:	58                   	pop    %rax
1d03     1d03:	fa                   	cli
1d04     1d04:	9c                   	pushf
1d05     1d05:	58                   	pop    %rax
1d06     1d06:	fa                   	cli
1d07     1d07:	9c                   	pushf
1d08     1d08:	58                   	pop    %rax
1d09     1d09:	fa                   	cli
1d0a     1d0a:	9c                   	pushf
1d0b     1d0b:	58                   	pop    %rax
1d0c     1d0c:	fa                   	cli
1d0d     1d0d:	9c                   	pushf
1d0e     1d0e:	58                   	pop    %rax
1d0f     1d0f:	fa                   	cli
1d10     1d10:	9c                   	pushf
1d11     1d11:	58                   	pop    %rax
1d12     1d12:	fb                   	sti
1d13     1d13:	9c                   	pushf
1d14     1d14:	58                   	pop    %rax
1d15     1d15:	fa                   	cli
1d16     1d16:	9c                   	pushf
1d17     1d17:	58                   	pop    %rax
1d18     1d18:	fa                   	cli
1d19     1d19:	c6 07 00             	movb   $0x0,(%rdi)
1d1c     1d1c:	9c                   	pushf
1d1d     1d1d:	58                   	pop    %rax
1d1e     1d1e:	fb                   	sti
1d1f     1d1f:	c6 07 00             	movb   $0x0,(%rdi)
1d22     1d22:	9c                   	pushf
1d23     1d23:	58                   	pop    %rax
1d24     1d24:	9c                   	pushf
1d25     1d25:	58                   	pop    %rax
1d26     1d26:	fa                   	cli
1d27     1d27:	9c                   	pushf
1d28     1d28:	58                   	pop    %rax
1d29     1d29:	fb                   	sti
1d2a     1d2a:	9c                   	pushf
1d2b     1d2b:	58                   	pop    %rax
1d2c     1d2c:	fa                   	cli
1d2d     1d2d:	9c                   	pushf
1d2e     1d2e:	58                   	pop    %rax
1d2f     1d2f:	fb                   	sti
1d30     1d30:	9c                   	pushf
1d31     1d31:	58                   	pop    %rax
1d32     1d32:	fa                   	cli
1d33     1d33:	9c                   	pushf
1d34     1d34:	58                   	pop    %rax
1d35     1d35:	fb                   	sti
1d36     1d36:	9c                   	pushf
1d37     1d37:	58                   	pop    %rax
1d38     1d38:	fa                   	cli
1d39     1d39:	9c                   	pushf
1d3a     1d3a:	58                   	pop    %rax
1d3b     1d3b:	fb                   	sti
1d3c     1d3c:	9c                   	pushf
1d3d     1d3d:	58                   	pop    %rax
1d3e     1d3e:	fa                   	cli
1d3f     1d3f:	c6 07 00             	movb   $0x0,(%rdi)
1d42     1d42:	9c                   	pushf
1d43     1d43:	58                   	pop    %rax
1d44     1d44:	fb                   	sti
1d45     1d45:	9c                   	pushf
1d46     1d46:	58                   	pop    %rax
1d47     1d47:	fa                   	cli
1d48     1d48:	9c                   	pushf
1d49     1d49:	58                   	pop    %rax
1d4a     1d4a:	fa                   	cli
1d4b     1d4b:	9c                   	pushf
1d4c     1d4c:	58                   	pop    %rax
1d4d     1d4d:	fb                   	sti
1d4e     1d4e:	9c                   	pushf
1d4f     1d4f:	58                   	pop    %rax
1d50     1d50:	fa                   	cli
1d51     1d51:	9c                   	pushf
1d52     1d52:	58                   	pop    %rax
1d53     1d53:	fa                   	cli
1d54     1d54:	9c                   	pushf
1d55     1d55:	58                   	pop    %rax
1d56     1d56:	fb                   	sti
1d57     1d57:	9c                   	pushf
1d58     1d58:	58                   	pop    %rax
1d59     1d59:	fa                   	cli
1d5a     1d5a:	9c                   	pushf
1d5b     1d5b:	58                   	pop    %rax
1d5c     1d5c:	fa                   	cli
1d5d     1d5d:	c6 07 00             	movb   $0x0,(%rdi)
1d60     1d60:	9c                   	pushf
1d61     1d61:	58                   	pop    %rax
1d62     1d62:	fb                   	sti
1d63     1d63:	9c                   	pushf
1d64     1d64:	58                   	pop    %rax
1d65     1d65:	fa                   	cli
1d66     1d66:	9c                   	pushf
1d67     1d67:	58                   	pop    %rax
1d68     1d68:	fa                   	cli
1d69     1d69:	fb                   	sti
1d6a     1d6a:	9c                   	pushf
1d6b     1d6b:	58                   	pop    %rax
1d6c     1d6c:	9c                   	pushf
1d6d     1d6d:	58                   	pop    %rax
1d6e     1d6e:	fa                   	cli
1d6f     1d6f:	9c                   	pushf
1d70     1d70:	58                   	pop    %rax
1d71     1d71:	fb                   	sti
1d72     1d72:	fb                   	sti
1d73     1d73:	fb                   	sti
1d74     1d74:	fb                   	sti
1d75     1d75:	48 be 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rsi
1d7f     1d7f:	e9 00 00 00 00       	jmp    1d84 <.altinstr_replacement+0x1d84>	1d80: R_X86_64_PC32	.text+0x61112d
1d84     1d84:	9c                   	pushf
1d85     1d85:	58                   	pop    %rax
1d86     1d86:	fa                   	cli
1d87     1d87:	9c                   	pushf
1d88     1d88:	58                   	pop    %rax
1d89     1d89:	fb                   	sti
1d8a     1d8a:	9c                   	pushf
1d8b     1d8b:	58                   	pop    %rax
1d8c     1d8c:	fa                   	cli
1d8d     1d8d:	9c                   	pushf
1d8e     1d8e:	58                   	pop    %rax
1d8f     1d8f:	fb                   	sti
1d90     1d90:	9c                   	pushf
1d91     1d91:	58                   	pop    %rax
1d92     1d92:	fa                   	cli
1d93     1d93:	fb                   	sti
1d94     1d94:	9c                   	pushf
1d95     1d95:	58                   	pop    %rax
1d96     1d96:	fa                   	cli
1d97     1d97:	9c                   	pushf
1d98     1d98:	58                   	pop    %rax
1d99     1d99:	fb                   	sti
1d9a     1d9a:	9c                   	pushf
1d9b     1d9b:	58                   	pop    %rax
1d9c     1d9c:	fa                   	cli
1d9d     1d9d:	fb                   	sti
1d9e     1d9e:	9c                   	pushf
1d9f     1d9f:	58                   	pop    %rax
1da0     1da0:	fa                   	cli
1da1     1da1:	9c                   	pushf
1da2     1da2:	58                   	pop    %rax
1da3     1da3:	fb                   	sti
1da4     1da4:	9c                   	pushf
1da5     1da5:	58                   	pop    %rax
1da6     1da6:	fa                   	cli
1da7     1da7:	9c                   	pushf
1da8     1da8:	58                   	pop    %rax
1da9     1da9:	fb                   	sti
1daa     1daa:	9c                   	pushf
1dab     1dab:	58                   	pop    %rax
1dac     1dac:	fa                   	cli
1dad     1dad:	9c                   	pushf
1dae     1dae:	58                   	pop    %rax
1daf     1daf:	fb                   	sti
1db0     1db0:	9c                   	pushf
1db1     1db1:	58                   	pop    %rax
1db2     1db2:	fa                   	cli
1db3     1db3:	9c                   	pushf
1db4     1db4:	58                   	pop    %rax
1db5     1db5:	fb                   	sti
1db6     1db6:	9c                   	pushf
1db7     1db7:	58                   	pop    %rax
1db8     1db8:	fa                   	cli
1db9     1db9:	9c                   	pushf
1dba     1dba:	58                   	pop    %rax
1dbb     1dbb:	fb                   	sti
1dbc     1dbc:	9c                   	pushf
1dbd     1dbd:	58                   	pop    %rax
1dbe     1dbe:	fa                   	cli
1dbf     1dbf:	fb                   	sti
1dc0     1dc0:	9c                   	pushf
1dc1     1dc1:	58                   	pop    %rax
1dc2     1dc2:	fa                   	cli
1dc3     1dc3:	fb                   	sti
1dc4     1dc4:	49 be 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r14
1dce     1dce:	0f 01 cb             	stac
1dd1     1dd1:	0f ae e8             	lfence
1dd4     1dd4:	0f 01 ca             	clac
1dd7     1dd7:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
1de1     1de1:	49 bf 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r15
1deb     1deb:	0f 01 cb             	stac
1dee     1dee:	0f ae e8             	lfence
1df1     1df1:	0f 01 ca             	clac
1df4     1df4:	0f 01 ca             	clac
1df7     1df7:	0f 01 ca             	clac
1dfa     1dfa:	9c                   	pushf
1dfb     1dfb:	58                   	pop    %rax
1dfc     1dfc:	fa                   	cli
1dfd     1dfd:	9c                   	pushf
1dfe     1dfe:	58                   	pop    %rax
1dff     1dff:	fb                   	sti
1e00     1e00:	9c                   	pushf
1e01     1e01:	58                   	pop    %rax
1e02     1e02:	fa                   	cli
1e03     1e03:	9c                   	pushf
1e04     1e04:	58                   	pop    %rax
1e05     1e05:	fb                   	sti
1e06     1e06:	9c                   	pushf
1e07     1e07:	58                   	pop    %rax
1e08     1e08:	9c                   	pushf
1e09     1e09:	58                   	pop    %rax
1e0a     1e0a:	fa                   	cli
1e0b     1e0b:	9c                   	pushf
1e0c     1e0c:	58                   	pop    %rax
1e0d     1e0d:	fb                   	sti
1e0e     1e0e:	e9 00 00 00 00       	jmp    1e13 <.altinstr_replacement+0x1e13>	1e0f: R_X86_64_PC32	.init.text+0xb55b4
1e13     1e13:	e9 00 00 00 00       	jmp    1e18 <.altinstr_replacement+0x1e18>	1e14: R_X86_64_PC32	.init.text+0xb565c
1e18     1e18:	e9 00 00 00 00       	jmp    1e1d <.altinstr_replacement+0x1e1d>	1e19: R_X86_64_PC32	.text+0x67d20b
1e1d     1e1d:	e9 00 00 00 00       	jmp    1e22 <.altinstr_replacement+0x1e22>	1e1e: R_X86_64_PC32	.text+0x67df02
1e22     1e22:	e8 00 00 00 00       	call   1e27 <.altinstr_replacement+0x1e27>	1e23: R_X86_64_PLT32	clear_page_rep-0x4
1e27     1e27:	e8 00 00 00 00       	call   1e2c <.altinstr_replacement+0x1e2c>	1e28: R_X86_64_PLT32	clear_page_erms-0x4
1e2c     1e2c:	e9 00 00 00 00       	jmp    1e31 <.altinstr_replacement+0x1e31>	1e2d: R_X86_64_PC32	.text+0x67e99e
1e31     1e31:	e9 00 00 00 00       	jmp    1e36 <.altinstr_replacement+0x1e36>	1e32: R_X86_64_PC32	.text+0x67f554
1e36     1e36:	9c                   	pushf
1e37     1e37:	58                   	pop    %rax
1e38     1e38:	fa                   	cli
1e39     1e39:	fb                   	sti
1e3a     1e3a:	49 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r13
1e44     1e44:	49 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r13
1e4e     1e4e:	0f 01 cb             	stac
1e51     1e51:	0f ae e8             	lfence
1e54     1e54:	0f 01 ca             	clac
1e57     1e57:	0f 01 ca             	clac
1e5a     1e5a:	49 be 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r14
1e64     1e64:	0f 01 cb             	stac
1e67     1e67:	0f ae e8             	lfence
1e6a     1e6a:	0f 01 ca             	clac
1e6d     1e6d:	0f 01 ca             	clac
1e70     1e70:	9c                   	pushf
1e71     1e71:	58                   	pop    %rax
1e72     1e72:	fa                   	cli
1e73     1e73:	fb                   	sti
1e74     1e74:	9c                   	pushf
1e75     1e75:	58                   	pop    %rax
1e76     1e76:	9c                   	pushf
1e77     1e77:	58                   	pop    %rax
1e78     1e78:	fa                   	cli
1e79     1e79:	9c                   	pushf
1e7a     1e7a:	58                   	pop    %rax
1e7b     1e7b:	fb                   	sti
1e7c     1e7c:	9c                   	pushf
1e7d     1e7d:	58                   	pop    %rax
1e7e     1e7e:	fa                   	cli
1e7f     1e7f:	9c                   	pushf
1e80     1e80:	58                   	pop    %rax
1e81     1e81:	fb                   	sti
1e82     1e82:	9c                   	pushf
1e83     1e83:	58                   	pop    %rax
1e84     1e84:	fa                   	cli
1e85     1e85:	9c                   	pushf
1e86     1e86:	58                   	pop    %rax
1e87     1e87:	fb                   	sti
1e88     1e88:	9c                   	pushf
1e89     1e89:	58                   	pop    %rax
1e8a     1e8a:	fa                   	cli
1e8b     1e8b:	9c                   	pushf
1e8c     1e8c:	58                   	pop    %rax
1e8d     1e8d:	fb                   	sti
1e8e     1e8e:	9c                   	pushf
1e8f     1e8f:	58                   	pop    %rax
1e90     1e90:	fb                   	sti
1e91     1e91:	9c                   	pushf
1e92     1e92:	58                   	pop    %rax
1e93     1e93:	9c                   	pushf
1e94     1e94:	58                   	pop    %rax
1e95     1e95:	9c                   	pushf
1e96     1e96:	58                   	pop    %rax
1e97     1e97:	fa                   	cli
1e98     1e98:	9c                   	pushf
1e99     1e99:	58                   	pop    %rax
1e9a     1e9a:	9c                   	pushf
1e9b     1e9b:	58                   	pop    %rax
1e9c     1e9c:	9c                   	pushf
1e9d     1e9d:	58                   	pop    %rax
1e9e     1e9e:	fa                   	cli
1e9f     1e9f:	9c                   	pushf
1ea0     1ea0:	58                   	pop    %rax
1ea1     1ea1:	9c                   	pushf
1ea2     1ea2:	58                   	pop    %rax
1ea3     1ea3:	fb                   	sti
1ea4     1ea4:	9c                   	pushf
1ea5     1ea5:	58                   	pop    %rax
1ea6     1ea6:	fb                   	sti
1ea7     1ea7:	9c                   	pushf
1ea8     1ea8:	58                   	pop    %rax
1ea9     1ea9:	fa                   	cli
1eaa     1eaa:	9c                   	pushf
1eab     1eab:	58                   	pop    %rax
1eac     1eac:	fb                   	sti
1ead     1ead:	9c                   	pushf
1eae     1eae:	58                   	pop    %rax
1eaf     1eaf:	fa                   	cli
1eb0     1eb0:	9c                   	pushf
1eb1     1eb1:	58                   	pop    %rax
1eb2     1eb2:	fb                   	sti
1eb3     1eb3:	9c                   	pushf
1eb4     1eb4:	58                   	pop    %rax
1eb5     1eb5:	fb                   	sti
1eb6     1eb6:	9c                   	pushf
1eb7     1eb7:	58                   	pop    %rax
1eb8     1eb8:	fb                   	sti
1eb9     1eb9:	9c                   	pushf
1eba     1eba:	58                   	pop    %rax
1ebb     1ebb:	fa                   	cli
1ebc     1ebc:	9c                   	pushf
1ebd     1ebd:	58                   	pop    %rax
1ebe     1ebe:	fb                   	sti
1ebf     1ebf:	9c                   	pushf
1ec0     1ec0:	58                   	pop    %rax
1ec1     1ec1:	9c                   	pushf
1ec2     1ec2:	58                   	pop    %rax
1ec3     1ec3:	9c                   	pushf
1ec4     1ec4:	58                   	pop    %rax
1ec5     1ec5:	9c                   	pushf
1ec6     1ec6:	58                   	pop    %rax
1ec7     1ec7:	9c                   	pushf
1ec8     1ec8:	58                   	pop    %rax
1ec9     1ec9:	9c                   	pushf
1eca     1eca:	58                   	pop    %rax
1ecb     1ecb:	9c                   	pushf
1ecc     1ecc:	58                   	pop    %rax
1ecd     1ecd:	e9 00 00 00 00       	jmp    1ed2 <.altinstr_replacement+0x1ed2>	1ece: R_X86_64_PC32	.text+0x719930
1ed2     1ed2:	e9 00 00 00 00       	jmp    1ed7 <.altinstr_replacement+0x1ed7>	1ed3: R_X86_64_PC32	.text+0x719951
1ed7     1ed7:	9c                   	pushf
1ed8     1ed8:	58                   	pop    %rax
1ed9     1ed9:	fa                   	cli
1eda     1eda:	9c                   	pushf
1edb     1edb:	58                   	pop    %rax
1edc     1edc:	fb                   	sti
1edd     1edd:	9c                   	pushf
1ede     1ede:	58                   	pop    %rax
1edf     1edf:	fa                   	cli
1ee0     1ee0:	9c                   	pushf
1ee1     1ee1:	58                   	pop    %rax
1ee2     1ee2:	fb                   	sti
1ee3     1ee3:	9c                   	pushf
1ee4     1ee4:	58                   	pop    %rax
1ee5     1ee5:	fa                   	cli
1ee6     1ee6:	c6 07 00             	movb   $0x0,(%rdi)
1ee9     1ee9:	9c                   	pushf
1eea     1eea:	58                   	pop    %rax
1eeb     1eeb:	fb                   	sti
1eec     1eec:	9c                   	pushf
1eed     1eed:	58                   	pop    %rax
1eee     1eee:	fa                   	cli
1eef     1eef:	9c                   	pushf
1ef0     1ef0:	58                   	pop    %rax
1ef1     1ef1:	fb                   	sti
1ef2     1ef2:	9c                   	pushf
1ef3     1ef3:	58                   	pop    %rax
1ef4     1ef4:	fa                   	cli
1ef5     1ef5:	9c                   	pushf
1ef6     1ef6:	58                   	pop    %rax
1ef7     1ef7:	fb                   	sti
1ef8     1ef8:	9c                   	pushf
1ef9     1ef9:	58                   	pop    %rax
1efa     1efa:	fa                   	cli
1efb     1efb:	9c                   	pushf
1efc     1efc:	58                   	pop    %rax
1efd     1efd:	fb                   	sti
1efe     1efe:	9c                   	pushf
1eff     1eff:	58                   	pop    %rax
1f00     1f00:	9c                   	pushf
1f01     1f01:	58                   	pop    %rax
1f02     1f02:	fa                   	cli
1f03     1f03:	9c                   	pushf
1f04     1f04:	58                   	pop    %rax
1f05     1f05:	fb                   	sti
1f06     1f06:	9c                   	pushf
1f07     1f07:	58                   	pop    %rax
1f08     1f08:	fa                   	cli
1f09     1f09:	9c                   	pushf
1f0a     1f0a:	58                   	pop    %rax
1f0b     1f0b:	fb                   	sti
1f0c     1f0c:	9c                   	pushf
1f0d     1f0d:	58                   	pop    %rax
1f0e     1f0e:	fa                   	cli
1f0f     1f0f:	c6 07 00             	movb   $0x0,(%rdi)
1f12     1f12:	9c                   	pushf
1f13     1f13:	58                   	pop    %rax
1f14     1f14:	fb                   	sti
1f15     1f15:	9c                   	pushf
1f16     1f16:	58                   	pop    %rax
1f17     1f17:	fa                   	cli
1f18     1f18:	9c                   	pushf
1f19     1f19:	58                   	pop    %rax
1f1a     1f1a:	fb                   	sti
1f1b     1f1b:	c6 07 00             	movb   $0x0,(%rdi)
1f1e     1f1e:	c6 07 00             	movb   $0x0,(%rdi)
1f21     1f21:	9c                   	pushf
1f22     1f22:	58                   	pop    %rax
1f23     1f23:	fa                   	cli
1f24     1f24:	c6 07 00             	movb   $0x0,(%rdi)
1f27     1f27:	9c                   	pushf
1f28     1f28:	58                   	pop    %rax
1f29     1f29:	fb                   	sti
1f2a     1f2a:	9c                   	pushf
1f2b     1f2b:	58                   	pop    %rax
1f2c     1f2c:	fa                   	cli
1f2d     1f2d:	9c                   	pushf
1f2e     1f2e:	58                   	pop    %rax
1f2f     1f2f:	fb                   	sti
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
1f3f     1f3f:	c6 07 00             	movb   $0x0,(%rdi)
1f42     1f42:	c6 07 00             	movb   $0x0,(%rdi)
1f45     1f45:	c6 07 00             	movb   $0x0,(%rdi)
1f48     1f48:	c6 07 00             	movb   $0x0,(%rdi)
1f4b     1f4b:	c6 07 00             	movb   $0x0,(%rdi)
1f4e     1f4e:	c6 07 00             	movb   $0x0,(%rdi)
1f51     1f51:	c6 07 00             	movb   $0x0,(%rdi)
1f54     1f54:	9c                   	pushf
1f55     1f55:	58                   	pop    %rax
1f56     1f56:	fa                   	cli
1f57     1f57:	c6 07 00             	movb   $0x0,(%rdi)
1f5a     1f5a:	9c                   	pushf
1f5b     1f5b:	58                   	pop    %rax
1f5c     1f5c:	fb                   	sti
1f5d     1f5d:	c6 07 00             	movb   $0x0,(%rdi)
1f60     1f60:	c6 07 00             	movb   $0x0,(%rdi)
1f63     1f63:	c6 07 00             	movb   $0x0,(%rdi)
1f66     1f66:	9c                   	pushf
1f67     1f67:	58                   	pop    %rax
1f68     1f68:	c6 07 00             	movb   $0x0,(%rdi)
1f6b     1f6b:	9c                   	pushf
1f6c     1f6c:	58                   	pop    %rax
1f6d     1f6d:	9c                   	pushf
1f6e     1f6e:	58                   	pop    %rax
1f6f     1f6f:	9c                   	pushf
1f70     1f70:	58                   	pop    %rax
1f71     1f71:	e8 00 00 00 00       	call   1f76 <.altinstr_replacement+0x1f76>	1f72: R_X86_64_PLT32	copy_user_generic_string-0x4
1f76     1f76:	e8 00 00 00 00       	call   1f7b <.altinstr_replacement+0x1f7b>	1f77: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
1f7b     1f7b:	9c                   	pushf
1f7c     1f7c:	58                   	pop    %rax
1f7d     1f7d:	9c                   	pushf
1f7e     1f7e:	58                   	pop    %rax
1f7f     1f7f:	e8 00 00 00 00       	call   1f84 <.altinstr_replacement+0x1f84>	1f80: R_X86_64_PLT32	copy_user_generic_string-0x4
1f84     1f84:	e8 00 00 00 00       	call   1f89 <.altinstr_replacement+0x1f89>	1f85: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
1f89     1f89:	9c                   	pushf
1f8a     1f8a:	58                   	pop    %rax
1f8b     1f8b:	9c                   	pushf
1f8c     1f8c:	58                   	pop    %rax
1f8d     1f8d:	9c                   	pushf
1f8e     1f8e:	58                   	pop    %rax
1f8f     1f8f:	fa                   	cli
1f90     1f90:	9c                   	pushf
1f91     1f91:	58                   	pop    %rax
1f92     1f92:	fb                   	sti
1f93     1f93:	9c                   	pushf
1f94     1f94:	58                   	pop    %rax
1f95     1f95:	c6 07 00             	movb   $0x0,(%rdi)
1f98     1f98:	9c                   	pushf
1f99     1f99:	58                   	pop    %rax
1f9a     1f9a:	fa                   	cli
1f9b     1f9b:	c6 07 00             	movb   $0x0,(%rdi)
1f9e     1f9e:	fb                   	sti
1f9f     1f9f:	c6 07 00             	movb   $0x0,(%rdi)
1fa2     1fa2:	9c                   	pushf
1fa3     1fa3:	58                   	pop    %rax
1fa4     1fa4:	fa                   	cli
1fa5     1fa5:	fb                   	sti
1fa6     1fa6:	c6 07 00             	movb   $0x0,(%rdi)
1fa9     1fa9:	9c                   	pushf
1faa     1faa:	58                   	pop    %rax
1fab     1fab:	fa                   	cli
1fac     1fac:	fb                   	sti
1fad     1fad:	9c                   	pushf
1fae     1fae:	58                   	pop    %rax
1faf     1faf:	fa                   	cli
1fb0     1fb0:	fb                   	sti
1fb1     1fb1:	9c                   	pushf
1fb2     1fb2:	58                   	pop    %rax
1fb3     1fb3:	fa                   	cli
1fb4     1fb4:	fb                   	sti
1fb5     1fb5:	9c                   	pushf
1fb6     1fb6:	58                   	pop    %rax
1fb7     1fb7:	fa                   	cli
1fb8     1fb8:	9c                   	pushf
1fb9     1fb9:	58                   	pop    %rax
1fba     1fba:	fb                   	sti
1fbb     1fbb:	9c                   	pushf
1fbc     1fbc:	58                   	pop    %rax
1fbd     1fbd:	fa                   	cli
1fbe     1fbe:	9c                   	pushf
1fbf     1fbf:	58                   	pop    %rax
1fc0     1fc0:	fb                   	sti
1fc1     1fc1:	9c                   	pushf
1fc2     1fc2:	58                   	pop    %rax
1fc3     1fc3:	fa                   	cli
1fc4     1fc4:	9c                   	pushf
1fc5     1fc5:	58                   	pop    %rax
1fc6     1fc6:	fb                   	sti
1fc7     1fc7:	9c                   	pushf
1fc8     1fc8:	58                   	pop    %rax
1fc9     1fc9:	9c                   	pushf
1fca     1fca:	58                   	pop    %rax
1fcb     1fcb:	9c                   	pushf
1fcc     1fcc:	58                   	pop    %rax
1fcd     1fcd:	9c                   	pushf
1fce     1fce:	58                   	pop    %rax
1fcf     1fcf:	9c                   	pushf
1fd0     1fd0:	58                   	pop    %rax
1fd1     1fd1:	9c                   	pushf
1fd2     1fd2:	58                   	pop    %rax
1fd3     1fd3:	9c                   	pushf
1fd4     1fd4:	58                   	pop    %rax
1fd5     1fd5:	9c                   	pushf
1fd6     1fd6:	58                   	pop    %rax
1fd7     1fd7:	9c                   	pushf
1fd8     1fd8:	58                   	pop    %rax
1fd9     1fd9:	9c                   	pushf
1fda     1fda:	58                   	pop    %rax
1fdb     1fdb:	9c                   	pushf
1fdc     1fdc:	58                   	pop    %rax
1fdd     1fdd:	9c                   	pushf
1fde     1fde:	58                   	pop    %rax
1fdf     1fdf:	9c                   	pushf
1fe0     1fe0:	58                   	pop    %rax
1fe1     1fe1:	9c                   	pushf
1fe2     1fe2:	58                   	pop    %rax
1fe3     1fe3:	9c                   	pushf
1fe4     1fe4:	58                   	pop    %rax
1fe5     1fe5:	9c                   	pushf
1fe6     1fe6:	58                   	pop    %rax
1fe7     1fe7:	9c                   	pushf
1fe8     1fe8:	58                   	pop    %rax
1fe9     1fe9:	9c                   	pushf
1fea     1fea:	58                   	pop    %rax
1feb     1feb:	9c                   	pushf
1fec     1fec:	58                   	pop    %rax
1fed     1fed:	c6 07 00             	movb   $0x0,(%rdi)
1ff0     1ff0:	9c                   	pushf
1ff1     1ff1:	58                   	pop    %rax
1ff2     1ff2:	9c                   	pushf
1ff3     1ff3:	58                   	pop    %rax
1ff4     1ff4:	fa                   	cli
1ff5     1ff5:	9c                   	pushf
1ff6     1ff6:	58                   	pop    %rax
1ff7     1ff7:	fb                   	sti
1ff8     1ff8:	9c                   	pushf
1ff9     1ff9:	58                   	pop    %rax
1ffa     1ffa:	fa                   	cli
1ffb     1ffb:	c6 07 00             	movb   $0x0,(%rdi)
1ffe     1ffe:	9c                   	pushf
1fff     1fff:	58                   	pop    %rax
2000     2000:	fb                   	sti
2001     2001:	9c                   	pushf
2002     2002:	58                   	pop    %rax
2003     2003:	fa                   	cli
2004     2004:	c6 07 00             	movb   $0x0,(%rdi)
2007     2007:	9c                   	pushf
2008     2008:	58                   	pop    %rax
2009     2009:	fb                   	sti
200a     200a:	9c                   	pushf
200b     200b:	58                   	pop    %rax
200c     200c:	9c                   	pushf
200d     200d:	58                   	pop    %rax
200e     200e:	fa                   	cli
200f     200f:	fb                   	sti
2010     2010:	9c                   	pushf
2011     2011:	58                   	pop    %rax
2012     2012:	9c                   	pushf
2013     2013:	58                   	pop    %rax
2014     2014:	9c                   	pushf
2015     2015:	58                   	pop    %rax
2016     2016:	9c                   	pushf
2017     2017:	58                   	pop    %rax
2018     2018:	fa                   	cli
2019     2019:	fb                   	sti
201a     201a:	9c                   	pushf
201b     201b:	58                   	pop    %rax
201c     201c:	fa                   	cli
201d     201d:	c6 07 00             	movb   $0x0,(%rdi)
2020     2020:	9c                   	pushf
2021     2021:	58                   	pop    %rax
2022     2022:	fb                   	sti
2023     2023:	c6 07 00             	movb   $0x0,(%rdi)
2026     2026:	fb                   	sti
2027     2027:	9c                   	pushf
2028     2028:	58                   	pop    %rax
2029     2029:	fa                   	cli
202a     202a:	9c                   	pushf
202b     202b:	58                   	pop    %rax
202c     202c:	fa                   	cli
202d     202d:	c6 07 00             	movb   $0x0,(%rdi)
2030     2030:	9c                   	pushf
2031     2031:	58                   	pop    %rax
2032     2032:	fb                   	sti
2033     2033:	9c                   	pushf
2034     2034:	58                   	pop    %rax
2035     2035:	9c                   	pushf
2036     2036:	58                   	pop    %rax
2037     2037:	9c                   	pushf
2038     2038:	58                   	pop    %rax
2039     2039:	9c                   	pushf
203a     203a:	58                   	pop    %rax
203b     203b:	fa                   	cli
203c     203c:	9c                   	pushf
203d     203d:	58                   	pop    %rax
203e     203e:	fb                   	sti
203f     203f:	9c                   	pushf
2040     2040:	58                   	pop    %rax
2041     2041:	fa                   	cli
2042     2042:	9c                   	pushf
2043     2043:	58                   	pop    %rax
2044     2044:	fb                   	sti
2045     2045:	9c                   	pushf
2046     2046:	58                   	pop    %rax
2047     2047:	fa                   	cli
2048     2048:	9c                   	pushf
2049     2049:	58                   	pop    %rax
204a     204a:	fb                   	sti
204b     204b:	9c                   	pushf
204c     204c:	58                   	pop    %rax
204d     204d:	fa                   	cli
204e     204e:	9c                   	pushf
204f     204f:	58                   	pop    %rax
2050     2050:	fb                   	sti
2051     2051:	9c                   	pushf
2052     2052:	58                   	pop    %rax
2053     2053:	fa                   	cli
2054     2054:	9c                   	pushf
2055     2055:	58                   	pop    %rax
2056     2056:	fb                   	sti
2057     2057:	9c                   	pushf
2058     2058:	58                   	pop    %rax
2059     2059:	9c                   	pushf
205a     205a:	58                   	pop    %rax
205b     205b:	9c                   	pushf
205c     205c:	58                   	pop    %rax
205d     205d:	9c                   	pushf
205e     205e:	58                   	pop    %rax
205f     205f:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
2069     2069:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
2073     2073:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
207d     207d:	48 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbp
2087     2087:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
2091     2091:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
209b     209b:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
20a5     20a5:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
20af     20af:	9c                   	pushf
20b0     20b0:	58                   	pop    %rax
20b1     20b1:	9c                   	pushf
20b2     20b2:	58                   	pop    %rax
20b3     20b3:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
20bd     20bd:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
20c7     20c7:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
20d1     20d1:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
20db     20db:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
20e5     20e5:	48 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbp
20ef     20ef:	9c                   	pushf
20f0     20f0:	58                   	pop    %rax
20f1     20f1:	fa                   	cli
20f2     20f2:	fb                   	sti
20f3     20f3:	9c                   	pushf
20f4     20f4:	58                   	pop    %rax
20f5     20f5:	e9 00 00 00 00       	jmp    20fa <.altinstr_replacement+0x20fa>	20f6: R_X86_64_PC32	.text+0x870838
20fa     20fa:	9c                   	pushf
20fb     20fb:	58                   	pop    %rax
20fc     20fc:	9c                   	pushf
20fd     20fd:	58                   	pop    %rax
20fe     20fe:	fa                   	cli
20ff     20ff:	c6 07 00             	movb   $0x0,(%rdi)
2102     2102:	9c                   	pushf
2103     2103:	58                   	pop    %rax
2104     2104:	fb                   	sti
2105     2105:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
210f     210f:	9c                   	pushf
2110     2110:	58                   	pop    %rax
2111     2111:	9c                   	pushf
2112     2112:	58                   	pop    %rax
2113     2113:	fa                   	cli
2114     2114:	9c                   	pushf
2115     2115:	58                   	pop    %rax
2116     2116:	fb                   	sti
2117     2117:	9c                   	pushf
2118     2118:	58                   	pop    %rax
2119     2119:	fa                   	cli
211a     211a:	9c                   	pushf
211b     211b:	58                   	pop    %rax
211c     211c:	fb                   	sti
211d     211d:	9c                   	pushf
211e     211e:	58                   	pop    %rax
211f     211f:	fa                   	cli
2120     2120:	9c                   	pushf
2121     2121:	58                   	pop    %rax
2122     2122:	fb                   	sti
2123     2123:	9c                   	pushf
2124     2124:	58                   	pop    %rax
2125     2125:	fa                   	cli
2126     2126:	9c                   	pushf
2127     2127:	58                   	pop    %rax
2128     2128:	fb                   	sti
2129     2129:	9c                   	pushf
212a     212a:	58                   	pop    %rax
212b     212b:	fa                   	cli
212c     212c:	9c                   	pushf
212d     212d:	58                   	pop    %rax
212e     212e:	fb                   	sti
212f     212f:	0f 0d 0b             	prefetchw (%rbx)
2132     2132:	9c                   	pushf
2133     2133:	58                   	pop    %rax
2134     2134:	9c                   	pushf
2135     2135:	58                   	pop    %rax
2136     2136:	fa                   	cli
2137     2137:	9c                   	pushf
2138     2138:	58                   	pop    %rax
2139     2139:	fb                   	sti
213a     213a:	e9 00 00 00 00       	jmp    213f <.altinstr_replacement+0x213f>	213b: R_X86_64_PC32	.text+0x94769e
213f     213f:	48 89 f8             	mov    %rdi,%rax
2142     2142:	9c                   	pushf
2143     2143:	58                   	pop    %rax
2144     2144:	fa                   	cli
2145     2145:	9c                   	pushf
2146     2146:	58                   	pop    %rax
2147     2147:	fb                   	sti
2148     2148:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
2152     2152:	e9 00 00 00 00       	jmp    2157 <.altinstr_replacement+0x2157>	2153: R_X86_64_PC32	.text+0x94ea1e
2157     2157:	e9 00 00 00 00       	jmp    215c <.altinstr_replacement+0x215c>	2158: R_X86_64_PC32	.text+0x955a70
215c     215c:	48 89 f8             	mov    %rdi,%rax
215f     215f:	48 89 f8             	mov    %rdi,%rax
2162     2162:	48 89 f8             	mov    %rdi,%rax
2165     2165:	48 89 f8             	mov    %rdi,%rax
2168     2168:	9c                   	pushf
2169     2169:	58                   	pop    %rax
216a     216a:	fa                   	cli
216b     216b:	9c                   	pushf
216c     216c:	58                   	pop    %rax
216d     216d:	fb                   	sti
216e     216e:	9c                   	pushf
216f     216f:	58                   	pop    %rax
2170     2170:	fa                   	cli
2171     2171:	9c                   	pushf
2172     2172:	58                   	pop    %rax
2173     2173:	fb                   	sti
2174     2174:	9c                   	pushf
2175     2175:	58                   	pop    %rax
2176     2176:	fb                   	sti
2177     2177:	9c                   	pushf
2178     2178:	58                   	pop    %rax
2179     2179:	fa                   	cli
217a     217a:	9c                   	pushf
217b     217b:	58                   	pop    %rax
217c     217c:	fb                   	sti
217d     217d:	9c                   	pushf
217e     217e:	58                   	pop    %rax
217f     217f:	fa                   	cli
2180     2180:	9c                   	pushf
2181     2181:	58                   	pop    %rax
2182     2182:	fb                   	sti
2183     2183:	9c                   	pushf
2184     2184:	58                   	pop    %rax
2185     2185:	fa                   	cli
2186     2186:	9c                   	pushf
2187     2187:	58                   	pop    %rax
2188     2188:	fb                   	sti
2189     2189:	f3 48 0f b8 c7       	popcnt %rdi,%rax
218e     218e:	f3 48 0f b8 c7       	popcnt %rdi,%rax
2193     2193:	49 be 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r14
219d     219d:	49 be 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r14
21a7     21a7:	9c                   	pushf
21a8     21a8:	58                   	pop    %rax
21a9     21a9:	48 89 f8             	mov    %rdi,%rax
21ac     21ac:	48 be 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rsi
21b6     21b6:	48 89 f8             	mov    %rdi,%rax
21b9     21b9:	9c                   	pushf
21ba     21ba:	58                   	pop    %rax
21bb     21bb:	9c                   	pushf
21bc     21bc:	58                   	pop    %rax
21bd     21bd:	fa                   	cli
21be     21be:	9c                   	pushf
21bf     21bf:	58                   	pop    %rax
21c0     21c0:	fb                   	sti
21c1     21c1:	9c                   	pushf
21c2     21c2:	58                   	pop    %rax
21c3     21c3:	9c                   	pushf
21c4     21c4:	58                   	pop    %rax
21c5     21c5:	fa                   	cli
21c6     21c6:	9c                   	pushf
21c7     21c7:	58                   	pop    %rax
21c8     21c8:	fb                   	sti
21c9     21c9:	9c                   	pushf
21ca     21ca:	58                   	pop    %rax
21cb     21cb:	fa                   	cli
21cc     21cc:	9c                   	pushf
21cd     21cd:	58                   	pop    %rax
21ce     21ce:	fb                   	sti
21cf     21cf:	e9 00 00 00 00       	jmp    21d4 <.altinstr_replacement+0x21d4>	21d0: R_X86_64_PC32	.text+0x99a1ed
21d4     21d4:	e9 00 00 00 00       	jmp    21d9 <.altinstr_replacement+0x21d9>	21d5: R_X86_64_PC32	.text+0x99a20e
21d9     21d9:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
21e3     21e3:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
21ed     21ed:	0f 01 cb             	stac
21f0     21f0:	0f ae e8             	lfence
21f3     21f3:	0f 01 ca             	clac
21f6     21f6:	0f 01 ca             	clac
21f9     21f9:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
2203     2203:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
220d     220d:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
2217     2217:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
2221     2221:	9c                   	pushf
2222     2222:	58                   	pop    %rax
2223     2223:	fa                   	cli
2224     2224:	9c                   	pushf
2225     2225:	58                   	pop    %rax
2226     2226:	fb                   	sti
2227     2227:	9c                   	pushf
2228     2228:	58                   	pop    %rax
2229     2229:	fa                   	cli
222a     222a:	9c                   	pushf
222b     222b:	58                   	pop    %rax
222c     222c:	fb                   	sti
222d     222d:	e9 00 00 00 00       	jmp    2232 <.altinstr_replacement+0x2232>	222e: R_X86_64_PC32	.text+0x9b2ff3
2232     2232:	e9 00 00 00 00       	jmp    2237 <.altinstr_replacement+0x2237>	2233: R_X86_64_PC32	.text+0x9b304c
2237     2237:	48 89 f8             	mov    %rdi,%rax
223a     223a:	48 89 f8             	mov    %rdi,%rax
223d     223d:	48 89 f8             	mov    %rdi,%rax
2240     2240:	48 89 f8             	mov    %rdi,%rax
2243     2243:	48 89 f8             	mov    %rdi,%rax
2246     2246:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
2250     2250:	e8 00 00 00 00       	call   2255 <.altinstr_replacement+0x2255>	2251: R_X86_64_PLT32	copy_user_generic_string-0x4
2255     2255:	e8 00 00 00 00       	call   225a <.altinstr_replacement+0x225a>	2256: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
225a     225a:	49 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r13
2264     2264:	e8 00 00 00 00       	call   2269 <.altinstr_replacement+0x2269>	2265: R_X86_64_PLT32	copy_user_generic_string-0x4
2269     2269:	e8 00 00 00 00       	call   226e <.altinstr_replacement+0x226e>	226a: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
226e     226e:	9c                   	pushf
226f     226f:	58                   	pop    %rax
2270     2270:	fa                   	cli
2271     2271:	9c                   	pushf
2272     2272:	58                   	pop    %rax
2273     2273:	fb                   	sti
2274     2274:	9c                   	pushf
2275     2275:	58                   	pop    %rax
2276     2276:	fa                   	cli
2277     2277:	9c                   	pushf
2278     2278:	58                   	pop    %rax
2279     2279:	fb                   	sti
227a     227a:	9c                   	pushf
227b     227b:	58                   	pop    %rax
227c     227c:	fa                   	cli
227d     227d:	9c                   	pushf
227e     227e:	58                   	pop    %rax
227f     227f:	fb                   	sti
2280     2280:	9c                   	pushf
2281     2281:	58                   	pop    %rax
2282     2282:	fa                   	cli
2283     2283:	9c                   	pushf
2284     2284:	58                   	pop    %rax
2285     2285:	fb                   	sti
2286     2286:	9c                   	pushf
2287     2287:	58                   	pop    %rax
2288     2288:	fa                   	cli
2289     2289:	9c                   	pushf
228a     228a:	58                   	pop    %rax
228b     228b:	fb                   	sti
228c     228c:	48 89 f8             	mov    %rdi,%rax
228f     228f:	e9 00 00 00 00       	jmp    2294 <.altinstr_replacement+0x2294>	2290: R_X86_64_PC32	.text+0x9f5154
2294     2294:	e9 00 00 00 00       	jmp    2299 <.altinstr_replacement+0x2299>	2295: R_X86_64_PC32	.text+0x9f52a8
2299     2299:	0f 0d 4d f8          	prefetchw -0x8(%rbp)
229d     229d:	48 89 f8             	mov    %rdi,%rax
22a0     22a0:	48 89 f8             	mov    %rdi,%rax
22a3     22a3:	48 89 f8             	mov    %rdi,%rax
22a6     22a6:	48 89 f8             	mov    %rdi,%rax
22a9     22a9:	48 89 f8             	mov    %rdi,%rax
22ac     22ac:	48 89 f8             	mov    %rdi,%rax
22af     22af:	48 89 f8             	mov    %rdi,%rax
22b2     22b2:	e9 00 00 00 00       	jmp    22b7 <.altinstr_replacement+0x22b7>	22b3: R_X86_64_PC32	.text+0xa01b69
22b7     22b7:	e9 00 00 00 00       	jmp    22bc <.altinstr_replacement+0x22bc>	22b8: R_X86_64_PC32	.text+0xa01824
22bc     22bc:	48 89 f8             	mov    %rdi,%rax
22bf     22bf:	48 89 f8             	mov    %rdi,%rax
22c2     22c2:	48 89 f8             	mov    %rdi,%rax
22c5     22c5:	48 89 f8             	mov    %rdi,%rax
22c8     22c8:	48 89 f8             	mov    %rdi,%rax
22cb     22cb:	48 89 f8             	mov    %rdi,%rax
22ce     22ce:	48 89 f8             	mov    %rdi,%rax
22d1     22d1:	48 89 f8             	mov    %rdi,%rax
22d4     22d4:	f3 48 0f b8 c7       	popcnt %rdi,%rax
22d9     22d9:	48 89 f8             	mov    %rdi,%rax
22dc     22dc:	48 89 f8             	mov    %rdi,%rax
22df     22df:	9c                   	pushf
22e0     22e0:	58                   	pop    %rax
22e1     22e1:	fa                   	cli
22e2     22e2:	9c                   	pushf
22e3     22e3:	58                   	pop    %rax
22e4     22e4:	fb                   	sti
22e5     22e5:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
22ef     22ef:	49 bf 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r15
22f9     22f9:	49 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r13
2303     2303:	49 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r13
230d     230d:	e8 00 00 00 00       	call   2312 <.altinstr_replacement+0x2312>	230e: R_X86_64_PLT32	clear_page_rep-0x4
2312     2312:	e8 00 00 00 00       	call   2317 <.altinstr_replacement+0x2317>	2313: R_X86_64_PLT32	clear_page_erms-0x4
2317     2317:	e8 00 00 00 00       	call   231c <.altinstr_replacement+0x231c>	2318: R_X86_64_PLT32	clear_page_rep-0x4
231c     231c:	e8 00 00 00 00       	call   2321 <.altinstr_replacement+0x2321>	231d: R_X86_64_PLT32	clear_page_erms-0x4
2321     2321:	e8 00 00 00 00       	call   2326 <.altinstr_replacement+0x2326>	2322: R_X86_64_PLT32	clear_page_rep-0x4
2326     2326:	e8 00 00 00 00       	call   232b <.altinstr_replacement+0x232b>	2327: R_X86_64_PLT32	clear_page_erms-0x4
232b     232b:	e9 00 00 00 00       	jmp    2330 <.altinstr_replacement+0x2330>	232c: R_X86_64_PC32	.text+0xa2d791
2330     2330:	e9 00 00 00 00       	jmp    2335 <.altinstr_replacement+0x2335>	2331: R_X86_64_PC32	.init.text+0xd5abc
2335     2335:	48 89 f8             	mov    %rdi,%rax
2338     2338:	e9 00 00 00 00       	jmp    233d <.altinstr_replacement+0x233d>	2339: R_X86_64_PC32	.text.unlikely+0x71288
233d     233d:	48 89 f8             	mov    %rdi,%rax
2340     2340:	9c                   	pushf
2341     2341:	58                   	pop    %rax
2342     2342:	fa                   	cli
2343     2343:	9c                   	pushf
2344     2344:	58                   	pop    %rax
2345     2345:	fb                   	sti
2346     2346:	e9 00 00 00 00       	jmp    234b <.altinstr_replacement+0x234b>	2347: R_X86_64_PC32	.text.unlikely+0x7141d
234b     234b:	e9 00 00 00 00       	jmp    2350 <.altinstr_replacement+0x2350>	234c: R_X86_64_PC32	.text.unlikely+0x71380
2350     2350:	48 89 f8             	mov    %rdi,%rax
2353     2353:	48 89 f8             	mov    %rdi,%rax
2356     2356:	48 89 f8             	mov    %rdi,%rax
2359     2359:	e9 00 00 00 00       	jmp    235e <.altinstr_replacement+0x235e>	235a: R_X86_64_PC32	.init.text+0xd8f8d
235e     235e:	e9 00 00 00 00       	jmp    2363 <.altinstr_replacement+0x2363>	235f: R_X86_64_PC32	.init.text+0xd9008
2363     2363:	e9 00 00 00 00       	jmp    2368 <.altinstr_replacement+0x2368>	2364: R_X86_64_PC32	.init.text+0xd9572
2368     2368:	48 89 f8             	mov    %rdi,%rax
236b     236b:	48 89 f8             	mov    %rdi,%rax
236e     236e:	9c                   	pushf
236f     236f:	58                   	pop    %rax
2370     2370:	fa                   	cli
2371     2371:	9c                   	pushf
2372     2372:	58                   	pop    %rax
2373     2373:	fb                   	sti
2374     2374:	9c                   	pushf
2375     2375:	58                   	pop    %rax
2376     2376:	fa                   	cli
2377     2377:	9c                   	pushf
2378     2378:	58                   	pop    %rax
2379     2379:	fb                   	sti
237a     237a:	e9 00 00 00 00       	jmp    237f <.altinstr_replacement+0x237f>	237b: R_X86_64_PC32	.text+0xa53fba
237f     237f:	e9 00 00 00 00       	jmp    2384 <.altinstr_replacement+0x2384>	2380: R_X86_64_PC32	.text+0xa54005
2384     2384:	9c                   	pushf
2385     2385:	58                   	pop    %rax
2386     2386:	fa                   	cli
2387     2387:	9c                   	pushf
2388     2388:	58                   	pop    %rax
2389     2389:	fb                   	sti
238a     238a:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
2394     2394:	0f 01 cb             	stac
2397     2397:	0f ae e8             	lfence
239a     239a:	0f 01 ca             	clac
239d     239d:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
23a7     23a7:	0f 01 cb             	stac
23aa     23aa:	0f ae e8             	lfence
23ad     23ad:	0f 01 ca             	clac
23b0     23b0:	e9 00 00 00 00       	jmp    23b5 <.altinstr_replacement+0x23b5>	23b1: R_X86_64_PC32	.text+0xa67c5e
23b5     23b5:	48 89 f8             	mov    %rdi,%rax
23b8     23b8:	48 89 f8             	mov    %rdi,%rax
23bb     23bb:	e9 00 00 00 00       	jmp    23c0 <.altinstr_replacement+0x23c0>	23bc: R_X86_64_PC32	.text+0xa68708
23c0     23c0:	e9 00 00 00 00       	jmp    23c5 <.altinstr_replacement+0x23c5>	23c1: R_X86_64_PC32	.text+0xa68c04
23c5     23c5:	48 89 f8             	mov    %rdi,%rax
23c8     23c8:	48 89 f8             	mov    %rdi,%rax
23cb     23cb:	48 89 f8             	mov    %rdi,%rax
23ce     23ce:	e9 00 00 00 00       	jmp    23d3 <.altinstr_replacement+0x23d3>	23cf: R_X86_64_PC32	.text+0xa6d6c3
23d3     23d3:	48 89 f8             	mov    %rdi,%rax
23d6     23d6:	48 89 f8             	mov    %rdi,%rax
23d9     23d9:	e9 00 00 00 00       	jmp    23de <.altinstr_replacement+0x23de>	23da: R_X86_64_PC32	.text+0xa6d899
23de     23de:	e9 00 00 00 00       	jmp    23e3 <.altinstr_replacement+0x23e3>	23df: R_X86_64_PC32	.text+0xa6dbfe
23e3     23e3:	48 89 f8             	mov    %rdi,%rax
23e6     23e6:	48 89 f8             	mov    %rdi,%rax
23e9     23e9:	48 89 f8             	mov    %rdi,%rax
23ec     23ec:	48 89 f8             	mov    %rdi,%rax
23ef     23ef:	48 89 f8             	mov    %rdi,%rax
23f2     23f2:	48 89 f8             	mov    %rdi,%rax
23f5     23f5:	48 89 f8             	mov    %rdi,%rax
23f8     23f8:	48 89 f8             	mov    %rdi,%rax
23fb     23fb:	48 89 f8             	mov    %rdi,%rax
23fe     23fe:	48 89 f8             	mov    %rdi,%rax
2401     2401:	48 89 f8             	mov    %rdi,%rax
2404     2404:	48 89 f8             	mov    %rdi,%rax
2407     2407:	48 89 f8             	mov    %rdi,%rax
240a     240a:	48 89 f8             	mov    %rdi,%rax
240d     240d:	48 89 f8             	mov    %rdi,%rax
2410     2410:	e9 00 00 00 00       	jmp    2415 <.altinstr_replacement+0x2415>	2411: R_X86_64_PC32	.text+0xa6ff8d
2415     2415:	e9 00 00 00 00       	jmp    241a <.altinstr_replacement+0x241a>	2416: R_X86_64_PC32	.text+0xa6fffb
241a     241a:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
2424     2424:	e9 00 00 00 00       	jmp    2429 <.altinstr_replacement+0x2429>	2425: R_X86_64_PC32	.text+0xa7022a
2429     2429:	48 89 f8             	mov    %rdi,%rax
242c     242c:	48 89 f8             	mov    %rdi,%rax
242f     242f:	48 89 f8             	mov    %rdi,%rax
2432     2432:	48 89 f8             	mov    %rdi,%rax
2435     2435:	48 89 f8             	mov    %rdi,%rax
2438     2438:	48 89 f8             	mov    %rdi,%rax
243b     243b:	48 89 f8             	mov    %rdi,%rax
243e     243e:	e9 00 00 00 00       	jmp    2443 <.altinstr_replacement+0x2443>	243f: R_X86_64_PC32	.text+0xa72c71
2443     2443:	48 89 f8             	mov    %rdi,%rax
2446     2446:	48 89 f8             	mov    %rdi,%rax
2449     2449:	48 89 f8             	mov    %rdi,%rax
244c     244c:	48 89 f8             	mov    %rdi,%rax
244f     244f:	48 89 f8             	mov    %rdi,%rax
2452     2452:	48 89 f8             	mov    %rdi,%rax
2455     2455:	48 89 f8             	mov    %rdi,%rax
2458     2458:	48 89 f8             	mov    %rdi,%rax
245b     245b:	e9 00 00 00 00       	jmp    2460 <.altinstr_replacement+0x2460>	245c: R_X86_64_PC32	.text+0xa734b1
2460     2460:	48 89 f8             	mov    %rdi,%rax
2463     2463:	48 89 f8             	mov    %rdi,%rax
2466     2466:	48 89 f8             	mov    %rdi,%rax
2469     2469:	48 89 f8             	mov    %rdi,%rax
246c     246c:	48 89 f8             	mov    %rdi,%rax
246f     246f:	48 89 f8             	mov    %rdi,%rax
2472     2472:	48 89 f8             	mov    %rdi,%rax
2475     2475:	48 89 f8             	mov    %rdi,%rax
2478     2478:	48 89 f8             	mov    %rdi,%rax
247b     247b:	48 89 f8             	mov    %rdi,%rax
247e     247e:	e9 00 00 00 00       	jmp    2483 <.altinstr_replacement+0x2483>	247f: R_X86_64_PC32	.text+0xa74441
2483     2483:	48 89 f8             	mov    %rdi,%rax
2486     2486:	e9 00 00 00 00       	jmp    248b <.altinstr_replacement+0x248b>	2487: R_X86_64_PC32	.text+0xa7474c
248b     248b:	9c                   	pushf
248c     248c:	58                   	pop    %rax
248d     248d:	fa                   	cli
248e     248e:	9c                   	pushf
248f     248f:	58                   	pop    %rax
2490     2490:	fb                   	sti
2491     2491:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
249b     249b:	e9 00 00 00 00       	jmp    24a0 <.altinstr_replacement+0x24a0>	249c: R_X86_64_PC32	.text+0xa79480
24a0     24a0:	48 89 f8             	mov    %rdi,%rax
24a3     24a3:	48 89 f8             	mov    %rdi,%rax
24a6     24a6:	e9 00 00 00 00       	jmp    24ab <.altinstr_replacement+0x24ab>	24a7: R_X86_64_PC32	.text+0xa7999e
24ab     24ab:	48 89 f8             	mov    %rdi,%rax
24ae     24ae:	48 89 f8             	mov    %rdi,%rax
24b1     24b1:	48 89 f8             	mov    %rdi,%rax
24b4     24b4:	e9 00 00 00 00       	jmp    24b9 <.altinstr_replacement+0x24b9>	24b5: R_X86_64_PC32	.text+0xa79e6f
24b9     24b9:	e9 00 00 00 00       	jmp    24be <.altinstr_replacement+0x24be>	24ba: R_X86_64_PC32	.text+0xa79ec8
24be     24be:	9c                   	pushf
24bf     24bf:	58                   	pop    %rax
24c0     24c0:	fa                   	cli
24c1     24c1:	9c                   	pushf
24c2     24c2:	58                   	pop    %rax
24c3     24c3:	fb                   	sti
24c4     24c4:	9c                   	pushf
24c5     24c5:	58                   	pop    %rax
24c6     24c6:	fa                   	cli
24c7     24c7:	9c                   	pushf
24c8     24c8:	58                   	pop    %rax
24c9     24c9:	fb                   	sti
24ca     24ca:	e9 00 00 00 00       	jmp    24cf <.altinstr_replacement+0x24cf>	24cb: R_X86_64_PC32	.text+0xa7ac1c
24cf     24cf:	e9 00 00 00 00       	jmp    24d4 <.altinstr_replacement+0x24d4>	24d0: R_X86_64_PC32	.text+0xa7ac62
24d4     24d4:	48 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbp
24de     24de:	48 89 f8             	mov    %rdi,%rax
24e1     24e1:	48 89 f8             	mov    %rdi,%rax
24e4     24e4:	48 89 f8             	mov    %rdi,%rax
24e7     24e7:	48 89 f8             	mov    %rdi,%rax
24ea     24ea:	48 89 f8             	mov    %rdi,%rax
24ed     24ed:	48 89 f8             	mov    %rdi,%rax
24f0     24f0:	e9 00 00 00 00       	jmp    24f5 <.altinstr_replacement+0x24f5>	24f1: R_X86_64_PC32	.text+0xa7dad6
24f5     24f5:	e9 00 00 00 00       	jmp    24fa <.altinstr_replacement+0x24fa>	24f6: R_X86_64_PC32	.text+0xa7dae1
24fa     24fa:	48 89 f8             	mov    %rdi,%rax
24fd     24fd:	48 89 f8             	mov    %rdi,%rax
2500     2500:	48 89 f8             	mov    %rdi,%rax
2503     2503:	48 89 f8             	mov    %rdi,%rax
2506     2506:	48 89 f8             	mov    %rdi,%rax
2509     2509:	e9 00 00 00 00       	jmp    250e <.altinstr_replacement+0x250e>	250a: R_X86_64_PC32	.text+0xa7e85f
250e     250e:	e9 00 00 00 00       	jmp    2513 <.altinstr_replacement+0x2513>	250f: R_X86_64_PC32	.text+0xa7e8ca
2513     2513:	e9 00 00 00 00       	jmp    2518 <.altinstr_replacement+0x2518>	2514: R_X86_64_PC32	.text+0xa7e7e2
2518     2518:	48 89 f8             	mov    %rdi,%rax
251b     251b:	48 89 f8             	mov    %rdi,%rax
251e     251e:	e9 00 00 00 00       	jmp    2523 <.altinstr_replacement+0x2523>	251f: R_X86_64_PC32	.text+0xa7f0d3
2523     2523:	48 89 f8             	mov    %rdi,%rax
2526     2526:	48 89 f8             	mov    %rdi,%rax
2529     2529:	48 89 f8             	mov    %rdi,%rax
252c     252c:	e8 00 00 00 00       	call   2531 <.altinstr_replacement+0x2531>	252d: R_X86_64_PLT32	copy_user_generic_string-0x4
2531     2531:	e8 00 00 00 00       	call   2536 <.altinstr_replacement+0x2536>	2532: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
2536     2536:	e8 00 00 00 00       	call   253b <.altinstr_replacement+0x253b>	2537: R_X86_64_PLT32	copy_user_generic_string-0x4
253b     253b:	e8 00 00 00 00       	call   2540 <.altinstr_replacement+0x2540>	253c: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
2540     2540:	e8 00 00 00 00       	call   2545 <.altinstr_replacement+0x2545>	2541: R_X86_64_PLT32	clear_page_rep-0x4
2545     2545:	e8 00 00 00 00       	call   254a <.altinstr_replacement+0x254a>	2546: R_X86_64_PLT32	clear_page_erms-0x4
254a     254a:	48 89 f8             	mov    %rdi,%rax
254d     254d:	e9 00 00 00 00       	jmp    2552 <.altinstr_replacement+0x2552>	254e: R_X86_64_PC32	.text+0xa81dd8
2552     2552:	e9 00 00 00 00       	jmp    2557 <.altinstr_replacement+0x2557>	2553: R_X86_64_PC32	.text+0xa81e44
2557     2557:	48 89 f8             	mov    %rdi,%rax
255a     255a:	48 89 f8             	mov    %rdi,%rax
255d     255d:	48 89 f8             	mov    %rdi,%rax
2560     2560:	48 89 f8             	mov    %rdi,%rax
2563     2563:	48 89 f8             	mov    %rdi,%rax
2566     2566:	48 89 f8             	mov    %rdi,%rax
2569     2569:	48 89 f8             	mov    %rdi,%rax
256c     256c:	48 89 f8             	mov    %rdi,%rax
256f     256f:	48 89 f8             	mov    %rdi,%rax
2572     2572:	48 89 f8             	mov    %rdi,%rax
2575     2575:	48 89 f8             	mov    %rdi,%rax
2578     2578:	48 89 f8             	mov    %rdi,%rax
257b     257b:	e9 00 00 00 00       	jmp    2580 <.altinstr_replacement+0x2580>	257c: R_X86_64_PC32	.text+0xa8746e
2580     2580:	e9 00 00 00 00       	jmp    2585 <.altinstr_replacement+0x2585>	2581: R_X86_64_PC32	.text+0xa874d5
2585     2585:	48 89 f8             	mov    %rdi,%rax
2588     2588:	48 89 f8             	mov    %rdi,%rax
258b     258b:	48 89 f8             	mov    %rdi,%rax
258e     258e:	e9 00 00 00 00       	jmp    2593 <.altinstr_replacement+0x2593>	258f: R_X86_64_PC32	.text+0xa8e92c
2593     2593:	e9 00 00 00 00       	jmp    2598 <.altinstr_replacement+0x2598>	2594: R_X86_64_PC32	.text+0xa8e962
2598     2598:	48 89 f8             	mov    %rdi,%rax
259b     259b:	48 89 f8             	mov    %rdi,%rax
259e     259e:	48 89 f8             	mov    %rdi,%rax
25a1     25a1:	e9 00 00 00 00       	jmp    25a6 <.altinstr_replacement+0x25a6>	25a2: R_X86_64_PC32	.text+0xa8fba1
25a6     25a6:	e9 00 00 00 00       	jmp    25ab <.altinstr_replacement+0x25ab>	25a7: R_X86_64_PC32	.text+0xa8fc08
25ab     25ab:	e9 00 00 00 00       	jmp    25b0 <.altinstr_replacement+0x25b0>	25ac: R_X86_64_PC32	.text+0xa8fc4d
25b0     25b0:	48 89 f8             	mov    %rdi,%rax
25b3     25b3:	48 89 f8             	mov    %rdi,%rax
25b6     25b6:	48 89 f8             	mov    %rdi,%rax
25b9     25b9:	e9 00 00 00 00       	jmp    25be <.altinstr_replacement+0x25be>	25ba: R_X86_64_PC32	.text+0xa90f6c
25be     25be:	e9 00 00 00 00       	jmp    25c3 <.altinstr_replacement+0x25c3>	25bf: R_X86_64_PC32	.text+0xa90f8e
25c3     25c3:	e9 00 00 00 00       	jmp    25c8 <.altinstr_replacement+0x25c8>	25c4: R_X86_64_PC32	.text+0xa90e53
25c8     25c8:	48 89 f8             	mov    %rdi,%rax
25cb     25cb:	48 89 f8             	mov    %rdi,%rax
25ce     25ce:	48 89 f8             	mov    %rdi,%rax
25d1     25d1:	48 89 f8             	mov    %rdi,%rax
25d4     25d4:	48 89 f8             	mov    %rdi,%rax
25d7     25d7:	48 89 f8             	mov    %rdi,%rax
25da     25da:	48 89 f8             	mov    %rdi,%rax
25dd     25dd:	e9 00 00 00 00       	jmp    25e2 <.altinstr_replacement+0x25e2>	25de: R_X86_64_PC32	.text+0xa93654
25e2     25e2:	e9 00 00 00 00       	jmp    25e7 <.altinstr_replacement+0x25e7>	25e3: R_X86_64_PC32	.text+0xa937d2
25e7     25e7:	48 89 f8             	mov    %rdi,%rax
25ea     25ea:	48 89 f8             	mov    %rdi,%rax
25ed     25ed:	e8 00 00 00 00       	call   25f2 <.altinstr_replacement+0x25f2>	25ee: R_X86_64_PLT32	clear_page_rep-0x4
25f2     25f2:	e8 00 00 00 00       	call   25f7 <.altinstr_replacement+0x25f7>	25f3: R_X86_64_PLT32	clear_page_erms-0x4
25f7     25f7:	e8 00 00 00 00       	call   25fc <.altinstr_replacement+0x25fc>	25f8: R_X86_64_PLT32	clear_page_rep-0x4
25fc     25fc:	e8 00 00 00 00       	call   2601 <.altinstr_replacement+0x2601>	25fd: R_X86_64_PLT32	clear_page_erms-0x4
2601     2601:	e8 00 00 00 00       	call   2606 <.altinstr_replacement+0x2606>	2602: R_X86_64_PLT32	clear_page_rep-0x4
2606     2606:	e8 00 00 00 00       	call   260b <.altinstr_replacement+0x260b>	2607: R_X86_64_PLT32	clear_page_erms-0x4
260b     260b:	e8 00 00 00 00       	call   2610 <.altinstr_replacement+0x2610>	260c: R_X86_64_PLT32	clear_page_rep-0x4
2610     2610:	e8 00 00 00 00       	call   2615 <.altinstr_replacement+0x2615>	2611: R_X86_64_PLT32	clear_page_erms-0x4
2615     2615:	e8 00 00 00 00       	call   261a <.altinstr_replacement+0x261a>	2616: R_X86_64_PLT32	clear_page_rep-0x4
261a     261a:	e8 00 00 00 00       	call   261f <.altinstr_replacement+0x261f>	261b: R_X86_64_PLT32	clear_page_erms-0x4
261f     261f:	e9 00 00 00 00       	jmp    2624 <.altinstr_replacement+0x2624>	2620: R_X86_64_PC32	.text+0xa96a44
2624     2624:	e9 00 00 00 00       	jmp    2629 <.altinstr_replacement+0x2629>	2625: R_X86_64_PC32	.text+0xa96a4b
2629     2629:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
2633     2633:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
263d     263d:	48 89 f8             	mov    %rdi,%rax
2640     2640:	48 89 f8             	mov    %rdi,%rax
2643     2643:	48 89 f8             	mov    %rdi,%rax
2646     2646:	48 89 f8             	mov    %rdi,%rax
2649     2649:	48 89 f8             	mov    %rdi,%rax
264c     264c:	48 89 f8             	mov    %rdi,%rax
264f     264f:	48 89 f8             	mov    %rdi,%rax
2652     2652:	48 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbp
265c     265c:	48 89 f8             	mov    %rdi,%rax
265f     265f:	48 89 f8             	mov    %rdi,%rax
2662     2662:	48 89 f8             	mov    %rdi,%rax
2665     2665:	48 89 f8             	mov    %rdi,%rax
2668     2668:	48 89 f8             	mov    %rdi,%rax
266b     266b:	48 89 f8             	mov    %rdi,%rax
266e     266e:	48 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbp
2678     2678:	48 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbp
2682     2682:	49 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r13
268c     268c:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
2696     2696:	48 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbp
26a0     26a0:	48 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbp
26aa     26aa:	e9 00 00 00 00       	jmp    26af <.altinstr_replacement+0x26af>	26ab: R_X86_64_PC32	.text+0xab2ee0
26af     26af:	48 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbp
26b9     26b9:	48 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbp
26c3     26c3:	48 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbp
26cd     26cd:	e9 00 00 00 00       	jmp    26d2 <.altinstr_replacement+0x26d2>	26ce: R_X86_64_PC32	.text+0xab5b5e
26d2     26d2:	48 89 f8             	mov    %rdi,%rax
26d5     26d5:	48 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbp
26df     26df:	e9 00 00 00 00       	jmp    26e4 <.altinstr_replacement+0x26e4>	26e0: R_X86_64_PC32	.text+0xab601d
26e4     26e4:	e9 00 00 00 00       	jmp    26e9 <.altinstr_replacement+0x26e9>	26e5: R_X86_64_PC32	.text+0xab61ca
26e9     26e9:	e9 00 00 00 00       	jmp    26ee <.altinstr_replacement+0x26ee>	26ea: R_X86_64_PC32	.text+0xab63d9
26ee     26ee:	e9 00 00 00 00       	jmp    26f3 <.altinstr_replacement+0x26f3>	26ef: R_X86_64_PC32	.text+0xab6619
26f3     26f3:	48 89 f8             	mov    %rdi,%rax
26f6     26f6:	48 89 f8             	mov    %rdi,%rax
26f9     26f9:	48 89 f8             	mov    %rdi,%rax
26fc     26fc:	48 89 f8             	mov    %rdi,%rax
26ff     26ff:	e9 00 00 00 00       	jmp    2704 <.altinstr_replacement+0x2704>	2700: R_X86_64_PC32	.text+0xab73f3
2704     2704:	e9 00 00 00 00       	jmp    2709 <.altinstr_replacement+0x2709>	2705: R_X86_64_PC32	.text+0xab744c
2709     2709:	48 89 f8             	mov    %rdi,%rax
270c     270c:	48 89 f8             	mov    %rdi,%rax
270f     270f:	48 89 f8             	mov    %rdi,%rax
2712     2712:	48 89 f8             	mov    %rdi,%rax
2715     2715:	48 89 f8             	mov    %rdi,%rax
2718     2718:	48 89 f8             	mov    %rdi,%rax
271b     271b:	48 89 f8             	mov    %rdi,%rax
271e     271e:	48 89 f8             	mov    %rdi,%rax
2721     2721:	48 89 f8             	mov    %rdi,%rax
2724     2724:	48 89 f8             	mov    %rdi,%rax
2727     2727:	48 89 f8             	mov    %rdi,%rax
272a     272a:	48 89 f8             	mov    %rdi,%rax
272d     272d:	48 89 f8             	mov    %rdi,%rax
2730     2730:	e9 00 00 00 00       	jmp    2735 <.altinstr_replacement+0x2735>	2731: R_X86_64_PC32	.text+0xaba22b
2735     2735:	e9 00 00 00 00       	jmp    273a <.altinstr_replacement+0x273a>	2736: R_X86_64_PC32	.text+0xaba2b8
273a     273a:	e9 00 00 00 00       	jmp    273f <.altinstr_replacement+0x273f>	273b: R_X86_64_PC32	.text+0xaba31f
273f     273f:	48 89 f8             	mov    %rdi,%rax
2742     2742:	e9 00 00 00 00       	jmp    2747 <.altinstr_replacement+0x2747>	2743: R_X86_64_PC32	.text+0xabb0d1
2747     2747:	e9 00 00 00 00       	jmp    274c <.altinstr_replacement+0x274c>	2748: R_X86_64_PC32	.text+0xabb59c
274c     274c:	e9 00 00 00 00       	jmp    2751 <.altinstr_replacement+0x2751>	274d: R_X86_64_PC32	.text+0xabb91e
2751     2751:	48 89 f8             	mov    %rdi,%rax
2754     2754:	e9 00 00 00 00       	jmp    2759 <.altinstr_replacement+0x2759>	2755: R_X86_64_PC32	.text+0xabb9ee
2759     2759:	e9 00 00 00 00       	jmp    275e <.altinstr_replacement+0x275e>	275a: R_X86_64_PC32	.text+0xabba55
275e     275e:	48 89 f8             	mov    %rdi,%rax
2761     2761:	48 89 f8             	mov    %rdi,%rax
2764     2764:	48 89 f8             	mov    %rdi,%rax
2767     2767:	e9 00 00 00 00       	jmp    276c <.altinstr_replacement+0x276c>	2768: R_X86_64_PC32	.text+0xabc212
276c     276c:	48 89 f8             	mov    %rdi,%rax
276f     276f:	48 89 f8             	mov    %rdi,%rax
2772     2772:	48 89 f8             	mov    %rdi,%rax
2775     2775:	48 89 f8             	mov    %rdi,%rax
2778     2778:	48 89 f8             	mov    %rdi,%rax
277b     277b:	48 89 f8             	mov    %rdi,%rax
277e     277e:	48 89 f8             	mov    %rdi,%rax
2781     2781:	48 89 f8             	mov    %rdi,%rax
2784     2784:	48 89 f8             	mov    %rdi,%rax
2787     2787:	48 89 f8             	mov    %rdi,%rax
278a     278a:	48 89 f8             	mov    %rdi,%rax
278d     278d:	48 89 f8             	mov    %rdi,%rax
2790     2790:	48 89 f8             	mov    %rdi,%rax
2793     2793:	48 89 f8             	mov    %rdi,%rax
2796     2796:	48 89 f8             	mov    %rdi,%rax
2799     2799:	48 89 f8             	mov    %rdi,%rax
279c     279c:	48 89 f8             	mov    %rdi,%rax
279f     279f:	48 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbp
27a9     27a9:	48 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbp
27b3     27b3:	e9 00 00 00 00       	jmp    27b8 <.altinstr_replacement+0x27b8>	27b4: R_X86_64_PC32	.text+0xac0a1e
27b8     27b8:	48 89 f8             	mov    %rdi,%rax
27bb     27bb:	48 89 f8             	mov    %rdi,%rax
27be     27be:	e9 00 00 00 00       	jmp    27c3 <.altinstr_replacement+0x27c3>	27bf: R_X86_64_PC32	.text+0xac0b6d
27c3     27c3:	e9 00 00 00 00       	jmp    27c8 <.altinstr_replacement+0x27c8>	27c4: R_X86_64_PC32	.text+0xac0bc3
27c8     27c8:	48 89 f8             	mov    %rdi,%rax
27cb     27cb:	48 89 f8             	mov    %rdi,%rax
27ce     27ce:	48 89 f8             	mov    %rdi,%rax
27d1     27d1:	48 89 f8             	mov    %rdi,%rax
27d4     27d4:	48 89 f8             	mov    %rdi,%rax
27d7     27d7:	e9 00 00 00 00       	jmp    27dc <.altinstr_replacement+0x27dc>	27d8: R_X86_64_PC32	.text+0xac1d3f
27dc     27dc:	48 89 f8             	mov    %rdi,%rax
27df     27df:	48 89 f8             	mov    %rdi,%rax
27e2     27e2:	48 89 f8             	mov    %rdi,%rax
27e5     27e5:	48 89 f8             	mov    %rdi,%rax
27e8     27e8:	48 89 f8             	mov    %rdi,%rax
27eb     27eb:	48 89 f8             	mov    %rdi,%rax
27ee     27ee:	48 89 f8             	mov    %rdi,%rax
27f1     27f1:	48 89 f8             	mov    %rdi,%rax
27f4     27f4:	48 89 f8             	mov    %rdi,%rax
27f7     27f7:	48 89 f8             	mov    %rdi,%rax
27fa     27fa:	48 89 f8             	mov    %rdi,%rax
27fd     27fd:	48 89 f8             	mov    %rdi,%rax
2800     2800:	48 89 f8             	mov    %rdi,%rax
2803     2803:	48 89 f8             	mov    %rdi,%rax
2806     2806:	48 89 f8             	mov    %rdi,%rax
2809     2809:	48 89 f8             	mov    %rdi,%rax
280c     280c:	48 89 f8             	mov    %rdi,%rax
280f     280f:	48 89 f8             	mov    %rdi,%rax
2812     2812:	48 89 f8             	mov    %rdi,%rax
2815     2815:	48 89 f8             	mov    %rdi,%rax
2818     2818:	48 89 f8             	mov    %rdi,%rax
281b     281b:	48 89 f8             	mov    %rdi,%rax
281e     281e:	e9 00 00 00 00       	jmp    2823 <.altinstr_replacement+0x2823>	281f: R_X86_64_PC32	.text+0xac4661
2823     2823:	48 89 f8             	mov    %rdi,%rax
2826     2826:	e9 00 00 00 00       	jmp    282b <.altinstr_replacement+0x282b>	2827: R_X86_64_PC32	.text+0xac4a4b
282b     282b:	e9 00 00 00 00       	jmp    2830 <.altinstr_replacement+0x2830>	282c: R_X86_64_PC32	.text+0xac4abb
2830     2830:	48 89 f8             	mov    %rdi,%rax
2833     2833:	48 89 f8             	mov    %rdi,%rax
2836     2836:	48 89 f8             	mov    %rdi,%rax
2839     2839:	e9 00 00 00 00       	jmp    283e <.altinstr_replacement+0x283e>	283a: R_X86_64_PC32	.text+0xac5e5b
283e     283e:	e9 00 00 00 00       	jmp    2843 <.altinstr_replacement+0x2843>	283f: R_X86_64_PC32	.text+0xac5e62
2843     2843:	48 89 f8             	mov    %rdi,%rax
2846     2846:	48 89 f8             	mov    %rdi,%rax
2849     2849:	48 89 f8             	mov    %rdi,%rax
284c     284c:	48 89 f8             	mov    %rdi,%rax
284f     284f:	48 89 f8             	mov    %rdi,%rax
2852     2852:	48 89 f8             	mov    %rdi,%rax
2855     2855:	48 89 f8             	mov    %rdi,%rax
2858     2858:	48 89 f8             	mov    %rdi,%rax
285b     285b:	e9 00 00 00 00       	jmp    2860 <.altinstr_replacement+0x2860>	285c: R_X86_64_PC32	.text+0xac909e
2860     2860:	48 89 f8             	mov    %rdi,%rax
2863     2863:	48 89 f8             	mov    %rdi,%rax
2866     2866:	48 89 f8             	mov    %rdi,%rax
2869     2869:	e9 00 00 00 00       	jmp    286e <.altinstr_replacement+0x286e>	286a: R_X86_64_PC32	.text+0xaceec2
286e     286e:	48 89 f8             	mov    %rdi,%rax
2871     2871:	48 89 f8             	mov    %rdi,%rax
2874     2874:	48 89 f8             	mov    %rdi,%rax
2877     2877:	48 89 f8             	mov    %rdi,%rax
287a     287a:	48 89 f8             	mov    %rdi,%rax
287d     287d:	48 89 f8             	mov    %rdi,%rax
2880     2880:	48 89 f8             	mov    %rdi,%rax
2883     2883:	48 89 f8             	mov    %rdi,%rax
2886     2886:	48 89 f8             	mov    %rdi,%rax
2889     2889:	48 89 f8             	mov    %rdi,%rax
288c     288c:	e9 00 00 00 00       	jmp    2891 <.altinstr_replacement+0x2891>	288d: R_X86_64_PC32	.text+0xad6cd3
2891     2891:	e9 00 00 00 00       	jmp    2896 <.altinstr_replacement+0x2896>	2892: R_X86_64_PC32	.text+0xad6ce2
2896     2896:	48 89 f8             	mov    %rdi,%rax
2899     2899:	48 89 f8             	mov    %rdi,%rax
289c     289c:	e9 00 00 00 00       	jmp    28a1 <.altinstr_replacement+0x28a1>	289d: R_X86_64_PC32	.text+0xada30d
28a1     28a1:	e9 00 00 00 00       	jmp    28a6 <.altinstr_replacement+0x28a6>	28a2: R_X86_64_PC32	.text+0xada5a7
28a6     28a6:	e9 00 00 00 00       	jmp    28ab <.altinstr_replacement+0x28ab>	28a7: R_X86_64_PC32	.text+0xada65e
28ab     28ab:	48 89 f8             	mov    %rdi,%rax
28ae     28ae:	48 89 f8             	mov    %rdi,%rax
28b1     28b1:	9c                   	pushf
28b2     28b2:	58                   	pop    %rax
28b3     28b3:	fa                   	cli
28b4     28b4:	9c                   	pushf
28b5     28b5:	58                   	pop    %rax
28b6     28b6:	fb                   	sti
28b7     28b7:	e9 00 00 00 00       	jmp    28bc <.altinstr_replacement+0x28bc>	28b8: R_X86_64_PC32	.text+0xadbf1a
28bc     28bc:	e9 00 00 00 00       	jmp    28c1 <.altinstr_replacement+0x28c1>	28bd: R_X86_64_PC32	.text+0xadbd49
28c1     28c1:	48 89 f8             	mov    %rdi,%rax
28c4     28c4:	e9 00 00 00 00       	jmp    28c9 <.altinstr_replacement+0x28c9>	28c5: R_X86_64_PC32	.text+0xadc83a
28c9     28c9:	48 89 f8             	mov    %rdi,%rax
28cc     28cc:	48 89 f8             	mov    %rdi,%rax
28cf     28cf:	48 89 f8             	mov    %rdi,%rax
28d2     28d2:	48 89 f8             	mov    %rdi,%rax
28d5     28d5:	48 89 f8             	mov    %rdi,%rax
28d8     28d8:	48 89 f8             	mov    %rdi,%rax
28db     28db:	e9 00 00 00 00       	jmp    28e0 <.altinstr_replacement+0x28e0>	28dc: R_X86_64_PC32	.text+0xadddb7
28e0     28e0:	e9 00 00 00 00       	jmp    28e5 <.altinstr_replacement+0x28e5>	28e1: R_X86_64_PC32	.text+0xadddd4
28e5     28e5:	e9 00 00 00 00       	jmp    28ea <.altinstr_replacement+0x28ea>	28e6: R_X86_64_PC32	.text+0xade007
28ea     28ea:	48 89 f8             	mov    %rdi,%rax
28ed     28ed:	48 89 f8             	mov    %rdi,%rax
28f0     28f0:	e9 00 00 00 00       	jmp    28f5 <.altinstr_replacement+0x28f5>	28f1: R_X86_64_PC32	.text+0xadf855
28f5     28f5:	e9 00 00 00 00       	jmp    28fa <.altinstr_replacement+0x28fa>	28f6: R_X86_64_PC32	.text+0xadf8bc
28fa     28fa:	48 89 f8             	mov    %rdi,%rax
28fd     28fd:	48 89 f8             	mov    %rdi,%rax
2900     2900:	48 89 f8             	mov    %rdi,%rax
2903     2903:	48 89 f8             	mov    %rdi,%rax
2906     2906:	48 89 f8             	mov    %rdi,%rax
2909     2909:	48 89 f8             	mov    %rdi,%rax
290c     290c:	48 89 f8             	mov    %rdi,%rax
290f     290f:	e9 00 00 00 00       	jmp    2914 <.altinstr_replacement+0x2914>	2910: R_X86_64_PC32	.text+0xae40a4
2914     2914:	e9 00 00 00 00       	jmp    2919 <.altinstr_replacement+0x2919>	2915: R_X86_64_PC32	.text+0xae4a07
2919     2919:	e9 00 00 00 00       	jmp    291e <.altinstr_replacement+0x291e>	291a: R_X86_64_PC32	.init.text+0xdbf11
291e     291e:	e9 00 00 00 00       	jmp    2923 <.altinstr_replacement+0x2923>	291f: R_X86_64_PC32	.text+0xae7d7e
2923     2923:	e9 00 00 00 00       	jmp    2928 <.altinstr_replacement+0x2928>	2924: R_X86_64_PC32	.text+0xae7e06
2928     2928:	e9 00 00 00 00       	jmp    292d <.altinstr_replacement+0x292d>	2929: R_X86_64_PC32	.text+0xae7e70
292d     292d:	e9 00 00 00 00       	jmp    2932 <.altinstr_replacement+0x2932>	292e: R_X86_64_PC32	.text+0xae8178
2932     2932:	e9 00 00 00 00       	jmp    2937 <.altinstr_replacement+0x2937>	2933: R_X86_64_PC32	.text+0xae87b1
2937     2937:	e9 00 00 00 00       	jmp    293c <.altinstr_replacement+0x293c>	2938: R_X86_64_PC32	.text+0xae89d4
293c     293c:	e9 00 00 00 00       	jmp    2941 <.altinstr_replacement+0x2941>	293d: R_X86_64_PC32	.text+0xae8d42
2941     2941:	e9 00 00 00 00       	jmp    2946 <.altinstr_replacement+0x2946>	2942: R_X86_64_PC32	.text+0xae8dff
2946     2946:	e9 00 00 00 00       	jmp    294b <.altinstr_replacement+0x294b>	2947: R_X86_64_PC32	.text+0xaea643
294b     294b:	e9 00 00 00 00       	jmp    2950 <.altinstr_replacement+0x2950>	294c: R_X86_64_PC32	.text+0xaeaf74
2950     2950:	e9 00 00 00 00       	jmp    2955 <.altinstr_replacement+0x2955>	2951: R_X86_64_PC32	.text+0xaeb06d
2955     2955:	e9 00 00 00 00       	jmp    295a <.altinstr_replacement+0x295a>	2956: R_X86_64_PC32	.text+0xaeb12d
295a     295a:	e9 00 00 00 00       	jmp    295f <.altinstr_replacement+0x295f>	295b: R_X86_64_PC32	.text+0xaecc17
295f     295f:	9c                   	pushf
2960     2960:	58                   	pop    %rax
2961     2961:	fa                   	cli
2962     2962:	9c                   	pushf
2963     2963:	58                   	pop    %rax
2964     2964:	fb                   	sti
2965     2965:	e9 00 00 00 00       	jmp    296a <.altinstr_replacement+0x296a>	2966: R_X86_64_PC32	.text+0xaf06bc
296a     296a:	e9 00 00 00 00       	jmp    296f <.altinstr_replacement+0x296f>	296b: R_X86_64_PC32	.text+0xaf06e9
296f     296f:	e8 00 00 00 00       	call   2974 <.altinstr_replacement+0x2974>	2970: R_X86_64_PLT32	clear_page_rep-0x4
2974     2974:	e8 00 00 00 00       	call   2979 <.altinstr_replacement+0x2979>	2975: R_X86_64_PLT32	clear_page_erms-0x4
2979     2979:	e9 00 00 00 00       	jmp    297e <.altinstr_replacement+0x297e>	297a: R_X86_64_PC32	.text+0xaf1236
297e     297e:	e9 00 00 00 00       	jmp    2983 <.altinstr_replacement+0x2983>	297f: R_X86_64_PC32	.text+0xaf147e
2983     2983:	e8 00 00 00 00       	call   2988 <.altinstr_replacement+0x2988>	2984: R_X86_64_PLT32	clear_page_rep-0x4
2988     2988:	e8 00 00 00 00       	call   298d <.altinstr_replacement+0x298d>	2989: R_X86_64_PLT32	clear_page_erms-0x4
298d     298d:	e9 00 00 00 00       	jmp    2992 <.altinstr_replacement+0x2992>	298e: R_X86_64_PC32	.text+0xaf2d57
2992     2992:	e9 00 00 00 00       	jmp    2997 <.altinstr_replacement+0x2997>	2993: R_X86_64_PC32	.text+0xaf373f
2997     2997:	e9 00 00 00 00       	jmp    299c <.altinstr_replacement+0x299c>	2998: R_X86_64_PC32	.text+0xaf3936
299c     299c:	e9 00 00 00 00       	jmp    29a1 <.altinstr_replacement+0x29a1>	299d: R_X86_64_PC32	.text+0xaf406d
29a1     29a1:	41 0f 0d 4d 00       	prefetchw 0x0(%r13)
29a6     29a6:	0f 0d 0b             	prefetchw (%rbx)
29a9     29a9:	e9 00 00 00 00       	jmp    29ae <.altinstr_replacement+0x29ae>	29aa: R_X86_64_PC32	.text+0xaf45db
29ae     29ae:	e9 00 00 00 00       	jmp    29b3 <.altinstr_replacement+0x29b3>	29af: R_X86_64_PC32	.text+0xaf4608
29b3     29b3:	e9 00 00 00 00       	jmp    29b8 <.altinstr_replacement+0x29b8>	29b4: R_X86_64_PC32	.text+0xaf4612
29b8     29b8:	e9 00 00 00 00       	jmp    29bd <.altinstr_replacement+0x29bd>	29b9: R_X86_64_PC32	.text+0xaf43fd
29bd     29bd:	e8 00 00 00 00       	call   29c2 <.altinstr_replacement+0x29c2>	29be: R_X86_64_PLT32	clear_page_rep-0x4
29c2     29c2:	e8 00 00 00 00       	call   29c7 <.altinstr_replacement+0x29c7>	29c3: R_X86_64_PLT32	clear_page_erms-0x4
29c7     29c7:	e9 00 00 00 00       	jmp    29cc <.altinstr_replacement+0x29cc>	29c8: R_X86_64_PC32	.text+0xaf4e16
29cc     29cc:	e9 00 00 00 00       	jmp    29d1 <.altinstr_replacement+0x29d1>	29cd: R_X86_64_PC32	.text+0xaf5366
29d1     29d1:	9c                   	pushf
29d2     29d2:	58                   	pop    %rax
29d3     29d3:	fa                   	cli
29d4     29d4:	9c                   	pushf
29d5     29d5:	58                   	pop    %rax
29d6     29d6:	fb                   	sti
29d7     29d7:	e9 00 00 00 00       	jmp    29dc <.altinstr_replacement+0x29dc>	29d8: R_X86_64_PC32	.text+0xaf7c9d
29dc     29dc:	e9 00 00 00 00       	jmp    29e1 <.altinstr_replacement+0x29e1>	29dd: R_X86_64_PC32	.text+0xaf7cbc
29e1     29e1:	9c                   	pushf
29e2     29e2:	58                   	pop    %rax
29e3     29e3:	fa                   	cli
29e4     29e4:	9c                   	pushf
29e5     29e5:	58                   	pop    %rax
29e6     29e6:	fb                   	sti
29e7     29e7:	e9 00 00 00 00       	jmp    29ec <.altinstr_replacement+0x29ec>	29e8: R_X86_64_PC32	.text+0xaf936e
29ec     29ec:	e9 00 00 00 00       	jmp    29f1 <.altinstr_replacement+0x29f1>	29ed: R_X86_64_PC32	.text+0xaf9650
29f1     29f1:	9c                   	pushf
29f2     29f2:	58                   	pop    %rax
29f3     29f3:	fa                   	cli
29f4     29f4:	9c                   	pushf
29f5     29f5:	58                   	pop    %rax
29f6     29f6:	fb                   	sti
29f7     29f7:	e8 00 00 00 00       	call   29fc <.altinstr_replacement+0x29fc>	29f8: R_X86_64_PLT32	clear_page_rep-0x4
29fc     29fc:	e8 00 00 00 00       	call   2a01 <.altinstr_replacement+0x2a01>	29fd: R_X86_64_PLT32	clear_page_erms-0x4
2a01     2a01:	e9 00 00 00 00       	jmp    2a06 <.altinstr_replacement+0x2a06>	2a02: R_X86_64_PC32	.text+0xb00d5d
2a06     2a06:	e9 00 00 00 00       	jmp    2a0b <.altinstr_replacement+0x2a0b>	2a07: R_X86_64_PC32	.text+0xb01bca
2a0b     2a0b:	e9 00 00 00 00       	jmp    2a10 <.altinstr_replacement+0x2a10>	2a0c: R_X86_64_PC32	.text+0xb0385a
2a10     2a10:	e9 00 00 00 00       	jmp    2a15 <.altinstr_replacement+0x2a15>	2a11: R_X86_64_PC32	.text+0xb03717
2a15     2a15:	e9 00 00 00 00       	jmp    2a1a <.altinstr_replacement+0x2a1a>	2a16: R_X86_64_PC32	.text+0xb03ee5
2a1a     2a1a:	e9 00 00 00 00       	jmp    2a1f <.altinstr_replacement+0x2a1f>	2a1b: R_X86_64_PC32	.text+0xb04169
2a1f     2a1f:	e9 00 00 00 00       	jmp    2a24 <.altinstr_replacement+0x2a24>	2a20: R_X86_64_PC32	.text+0xb04d0b
2a24     2a24:	e9 00 00 00 00       	jmp    2a29 <.altinstr_replacement+0x2a29>	2a25: R_X86_64_PC32	.text+0xb04e85
2a29     2a29:	e9 00 00 00 00       	jmp    2a2e <.altinstr_replacement+0x2a2e>	2a2a: R_X86_64_PC32	.text+0xb05da5
2a2e     2a2e:	e9 00 00 00 00       	jmp    2a33 <.altinstr_replacement+0x2a33>	2a2f: R_X86_64_PC32	.text+0xb06697
2a33     2a33:	e9 00 00 00 00       	jmp    2a38 <.altinstr_replacement+0x2a38>	2a34: R_X86_64_PC32	.text+0xb06cd7
2a38     2a38:	48 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbp
2a42     2a42:	48 89 f8             	mov    %rdi,%rax
2a45     2a45:	48 89 f8             	mov    %rdi,%rax
2a48     2a48:	48 89 f8             	mov    %rdi,%rax
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
2a78     2a78:	48 89 f8             	mov    %rdi,%rax
2a7b     2a7b:	48 89 f8             	mov    %rdi,%rax
2a7e     2a7e:	48 89 f8             	mov    %rdi,%rax
2a81     2a81:	48 89 f8             	mov    %rdi,%rax
2a84     2a84:	48 89 f8             	mov    %rdi,%rax
2a87     2a87:	48 89 f8             	mov    %rdi,%rax
2a8a     2a8a:	48 89 f8             	mov    %rdi,%rax
2a8d     2a8d:	48 89 f8             	mov    %rdi,%rax
2a90     2a90:	48 89 f8             	mov    %rdi,%rax
2a93     2a93:	48 89 f8             	mov    %rdi,%rax
2a96     2a96:	48 89 f8             	mov    %rdi,%rax
2a99     2a99:	48 89 f8             	mov    %rdi,%rax
2a9c     2a9c:	48 89 f8             	mov    %rdi,%rax
2a9f     2a9f:	48 89 f8             	mov    %rdi,%rax
2aa2     2aa2:	48 89 f8             	mov    %rdi,%rax
2aa5     2aa5:	48 89 f8             	mov    %rdi,%rax
2aa8     2aa8:	48 89 f8             	mov    %rdi,%rax
2aab     2aab:	48 89 f8             	mov    %rdi,%rax
2aae     2aae:	e9 00 00 00 00       	jmp    2ab3 <.altinstr_replacement+0x2ab3>	2aaf: R_X86_64_PC32	.text+0xb26f10
2ab3     2ab3:	e9 00 00 00 00       	jmp    2ab8 <.altinstr_replacement+0x2ab8>	2ab4: R_X86_64_PC32	.text+0xb26f77
2ab8     2ab8:	e9 00 00 00 00       	jmp    2abd <.altinstr_replacement+0x2abd>	2ab9: R_X86_64_PC32	.text+0xb2731f
2abd     2abd:	48 89 f8             	mov    %rdi,%rax
2ac0     2ac0:	48 89 f8             	mov    %rdi,%rax
2ac3     2ac3:	48 89 f8             	mov    %rdi,%rax
2ac6     2ac6:	48 89 f8             	mov    %rdi,%rax
2ac9     2ac9:	e9 00 00 00 00       	jmp    2ace <.altinstr_replacement+0x2ace>	2aca: R_X86_64_PC32	.init.text+0xe4ef2
2ace     2ace:	9c                   	pushf
2acf     2acf:	58                   	pop    %rax
2ad0     2ad0:	fa                   	cli
2ad1     2ad1:	9c                   	pushf
2ad2     2ad2:	58                   	pop    %rax
2ad3     2ad3:	fb                   	sti
2ad4     2ad4:	48 89 f8             	mov    %rdi,%rax
2ad7     2ad7:	e9 00 00 00 00       	jmp    2adc <.altinstr_replacement+0x2adc>	2ad8: R_X86_64_PC32	.text+0xb3461e
2adc     2adc:	48 89 f8             	mov    %rdi,%rax
2adf     2adf:	e9 00 00 00 00       	jmp    2ae4 <.altinstr_replacement+0x2ae4>	2ae0: R_X86_64_PC32	.text+0xb34cef
2ae4     2ae4:	e9 00 00 00 00       	jmp    2ae9 <.altinstr_replacement+0x2ae9>	2ae5: R_X86_64_PC32	.text+0xb34d48
2ae9     2ae9:	9c                   	pushf
2aea     2aea:	58                   	pop    %rax
2aeb     2aeb:	fa                   	cli
2aec     2aec:	9c                   	pushf
2aed     2aed:	58                   	pop    %rax
2aee     2aee:	fb                   	sti
2aef     2aef:	e9 00 00 00 00       	jmp    2af4 <.altinstr_replacement+0x2af4>	2af0: R_X86_64_PC32	.text+0xb3616a
2af4     2af4:	e9 00 00 00 00       	jmp    2af9 <.altinstr_replacement+0x2af9>	2af5: R_X86_64_PC32	.text+0xb362bd
2af9     2af9:	48 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbp
2b03     2b03:	48 89 f8             	mov    %rdi,%rax
2b06     2b06:	e9 00 00 00 00       	jmp    2b0b <.altinstr_replacement+0x2b0b>	2b07: R_X86_64_PC32	.text+0xb382e0
2b0b     2b0b:	e9 00 00 00 00       	jmp    2b10 <.altinstr_replacement+0x2b10>	2b0c: R_X86_64_PC32	.text+0xb3849b
2b10     2b10:	48 89 f8             	mov    %rdi,%rax
2b13     2b13:	48 89 f8             	mov    %rdi,%rax
2b16     2b16:	48 89 f8             	mov    %rdi,%rax
2b19     2b19:	48 89 f8             	mov    %rdi,%rax
2b1c     2b1c:	48 89 f8             	mov    %rdi,%rax
2b1f     2b1f:	48 89 f8             	mov    %rdi,%rax
2b22     2b22:	48 89 f8             	mov    %rdi,%rax
2b25     2b25:	e9 00 00 00 00       	jmp    2b2a <.altinstr_replacement+0x2b2a>	2b26: R_X86_64_PC32	.text+0xb47607
2b2a     2b2a:	48 89 f8             	mov    %rdi,%rax
2b2d     2b2d:	48 89 f8             	mov    %rdi,%rax
2b30     2b30:	48 89 f8             	mov    %rdi,%rax
2b33     2b33:	e9 00 00 00 00       	jmp    2b38 <.altinstr_replacement+0x2b38>	2b34: R_X86_64_PC32	.text+0xb47ee1
2b38     2b38:	48 89 f8             	mov    %rdi,%rax
2b3b     2b3b:	48 89 f8             	mov    %rdi,%rax
2b3e     2b3e:	48 89 f8             	mov    %rdi,%rax
2b41     2b41:	48 89 f8             	mov    %rdi,%rax
2b44     2b44:	48 89 f8             	mov    %rdi,%rax
2b47     2b47:	48 89 f8             	mov    %rdi,%rax
2b4a     2b4a:	48 89 f8             	mov    %rdi,%rax
2b4d     2b4d:	48 89 f8             	mov    %rdi,%rax
2b50     2b50:	48 89 f8             	mov    %rdi,%rax
2b53     2b53:	48 89 f8             	mov    %rdi,%rax
2b56     2b56:	48 89 f8             	mov    %rdi,%rax
2b59     2b59:	48 89 f8             	mov    %rdi,%rax
2b5c     2b5c:	48 89 f8             	mov    %rdi,%rax
2b5f     2b5f:	48 89 f8             	mov    %rdi,%rax
2b62     2b62:	48 89 f8             	mov    %rdi,%rax
2b65     2b65:	48 89 f8             	mov    %rdi,%rax
2b68     2b68:	e9 00 00 00 00       	jmp    2b6d <.altinstr_replacement+0x2b6d>	2b69: R_X86_64_PC32	.text+0xb51fde
2b6d     2b6d:	48 89 f8             	mov    %rdi,%rax
2b70     2b70:	48 89 f8             	mov    %rdi,%rax
2b73     2b73:	48 89 f8             	mov    %rdi,%rax
2b76     2b76:	48 89 f8             	mov    %rdi,%rax
2b79     2b79:	48 89 f8             	mov    %rdi,%rax
2b7c     2b7c:	48 89 f8             	mov    %rdi,%rax
2b7f     2b7f:	48 89 f8             	mov    %rdi,%rax
2b82     2b82:	48 89 f8             	mov    %rdi,%rax
2b85     2b85:	48 89 f8             	mov    %rdi,%rax
2b88     2b88:	48 89 f8             	mov    %rdi,%rax
2b8b     2b8b:	48 89 f8             	mov    %rdi,%rax
2b8e     2b8e:	48 89 f8             	mov    %rdi,%rax
2b91     2b91:	48 89 f8             	mov    %rdi,%rax
2b94     2b94:	48 89 f8             	mov    %rdi,%rax
2b97     2b97:	48 89 f8             	mov    %rdi,%rax
2b9a     2b9a:	48 89 f8             	mov    %rdi,%rax
2b9d     2b9d:	49 be 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r14
2ba7     2ba7:	0f 01 cb             	stac
2baa     2baa:	e8 00 00 00 00       	call   2baf <.altinstr_replacement+0x2baf>	2bab: R_X86_64_PLT32	clear_user_erms-0x4
2baf     2baf:	e8 00 00 00 00       	call   2bb4 <.altinstr_replacement+0x2bb4>	2bb0: R_X86_64_PLT32	clear_user_rep_good-0x4
2bb4     2bb4:	e8 00 00 00 00       	call   2bb9 <.altinstr_replacement+0x2bb9>	2bb5: R_X86_64_PLT32	clear_user_original-0x4
2bb9     2bb9:	0f 01 ca             	clac
2bbc     2bbc:	48 89 f8             	mov    %rdi,%rax
2bbf     2bbf:	48 89 f8             	mov    %rdi,%rax
2bc2     2bc2:	48 89 f8             	mov    %rdi,%rax
2bc5     2bc5:	48 89 f8             	mov    %rdi,%rax
2bc8     2bc8:	48 89 f8             	mov    %rdi,%rax
2bcb     2bcb:	48 89 f8             	mov    %rdi,%rax
2bce     2bce:	48 89 f8             	mov    %rdi,%rax
2bd1     2bd1:	48 89 f8             	mov    %rdi,%rax
2bd4     2bd4:	49 bf 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r15
2bde     2bde:	e9 00 00 00 00       	jmp    2be3 <.altinstr_replacement+0x2be3>	2bdf: R_X86_64_PC32	.text+0xb60cbe
2be3     2be3:	e9 00 00 00 00       	jmp    2be8 <.altinstr_replacement+0x2be8>	2be4: R_X86_64_PC32	.meminit.text+0xb51c
2be8     2be8:	e9 00 00 00 00       	jmp    2bed <.altinstr_replacement+0x2bed>	2be9: R_X86_64_PC32	.init.text+0xe9d67
2bed     2bed:	e9 00 00 00 00       	jmp    2bf2 <.altinstr_replacement+0x2bf2>	2bee: R_X86_64_PC32	.init.text+0xe9daf
2bf2     2bf2:	e9 00 00 00 00       	jmp    2bf7 <.altinstr_replacement+0x2bf7>	2bf3: R_X86_64_PC32	.init.text+0xea4c2
2bf7     2bf7:	e9 00 00 00 00       	jmp    2bfc <.altinstr_replacement+0x2bfc>	2bf8: R_X86_64_PC32	.text+0xb60fe2
2bfc     2bfc:	e9 00 00 00 00       	jmp    2c01 <.altinstr_replacement+0x2c01>	2bfd: R_X86_64_PC32	.text+0xb60fd7
2c01     2c01:	e9 00 00 00 00       	jmp    2c06 <.altinstr_replacement+0x2c06>	2c02: R_X86_64_PC32	.text+0xb613ef
2c06     2c06:	e9 00 00 00 00       	jmp    2c0b <.altinstr_replacement+0x2c0b>	2c07: R_X86_64_PC32	.text+0xb613f9
2c0b     2c0b:	e9 00 00 00 00       	jmp    2c10 <.altinstr_replacement+0x2c10>	2c0c: R_X86_64_PC32	.text+0xb6156f
2c10     2c10:	e9 00 00 00 00       	jmp    2c15 <.altinstr_replacement+0x2c15>	2c11: R_X86_64_PC32	.text+0xb61579
2c15     2c15:	48 89 f8             	mov    %rdi,%rax
2c18     2c18:	48 89 f8             	mov    %rdi,%rax
2c1b     2c1b:	48 89 f8             	mov    %rdi,%rax
2c1e     2c1e:	48 89 f8             	mov    %rdi,%rax
2c21     2c21:	e9 00 00 00 00       	jmp    2c26 <.altinstr_replacement+0x2c26>	2c22: R_X86_64_PC32	.text.unlikely+0x7a9a4
2c26     2c26:	48 89 f8             	mov    %rdi,%rax
2c29     2c29:	48 89 f8             	mov    %rdi,%rax
2c2c     2c2c:	e9 00 00 00 00       	jmp    2c31 <.altinstr_replacement+0x2c31>	2c2d: R_X86_64_PC32	.text.unlikely+0x7acb1
2c31     2c31:	e9 00 00 00 00       	jmp    2c36 <.altinstr_replacement+0x2c36>	2c32: R_X86_64_PC32	.text.unlikely+0x7ac14
2c36     2c36:	48 89 f8             	mov    %rdi,%rax
2c39     2c39:	48 89 f8             	mov    %rdi,%rax
2c3c     2c3c:	48 89 f8             	mov    %rdi,%rax
2c3f     2c3f:	48 89 f8             	mov    %rdi,%rax
2c42     2c42:	e9 00 00 00 00       	jmp    2c47 <.altinstr_replacement+0x2c47>	2c43: R_X86_64_PC32	.meminit.text+0xd3d3
2c47     2c47:	48 89 f8             	mov    %rdi,%rax
2c4a     2c4a:	48 89 f8             	mov    %rdi,%rax
2c4d     2c4d:	48 89 f8             	mov    %rdi,%rax
2c50     2c50:	48 89 f8             	mov    %rdi,%rax
2c53     2c53:	48 89 f8             	mov    %rdi,%rax
2c56     2c56:	48 89 f8             	mov    %rdi,%rax
2c59     2c59:	9c                   	pushf
2c5a     2c5a:	58                   	pop    %rax
2c5b     2c5b:	fa                   	cli
2c5c     2c5c:	9c                   	pushf
2c5d     2c5d:	58                   	pop    %rax
2c5e     2c5e:	fb                   	sti
2c5f     2c5f:	9c                   	pushf
2c60     2c60:	58                   	pop    %rax
2c61     2c61:	fa                   	cli
2c62     2c62:	9c                   	pushf
2c63     2c63:	58                   	pop    %rax
2c64     2c64:	fb                   	sti
2c65     2c65:	9c                   	pushf
2c66     2c66:	58                   	pop    %rax
2c67     2c67:	fb                   	sti
2c68     2c68:	9c                   	pushf
2c69     2c69:	58                   	pop    %rax
2c6a     2c6a:	fa                   	cli
2c6b     2c6b:	9c                   	pushf
2c6c     2c6c:	58                   	pop    %rax
2c6d     2c6d:	fb                   	sti
2c6e     2c6e:	9c                   	pushf
2c6f     2c6f:	58                   	pop    %rax
2c70     2c70:	fa                   	cli
2c71     2c71:	9c                   	pushf
2c72     2c72:	58                   	pop    %rax
2c73     2c73:	fb                   	sti
2c74     2c74:	9c                   	pushf
2c75     2c75:	58                   	pop    %rax
2c76     2c76:	fa                   	cli
2c77     2c77:	9c                   	pushf
2c78     2c78:	58                   	pop    %rax
2c79     2c79:	fb                   	sti
2c7a     2c7a:	9c                   	pushf
2c7b     2c7b:	58                   	pop    %rax
2c7c     2c7c:	fa                   	cli
2c7d     2c7d:	9c                   	pushf
2c7e     2c7e:	58                   	pop    %rax
2c7f     2c7f:	fa                   	cli
2c80     2c80:	9c                   	pushf
2c81     2c81:	58                   	pop    %rax
2c82     2c82:	fb                   	sti
2c83     2c83:	9c                   	pushf
2c84     2c84:	58                   	pop    %rax
2c85     2c85:	fb                   	sti
2c86     2c86:	9c                   	pushf
2c87     2c87:	58                   	pop    %rax
2c88     2c88:	fa                   	cli
2c89     2c89:	9c                   	pushf
2c8a     2c8a:	58                   	pop    %rax
2c8b     2c8b:	fb                   	sti
2c8c     2c8c:	9c                   	pushf
2c8d     2c8d:	58                   	pop    %rax
2c8e     2c8e:	9c                   	pushf
2c8f     2c8f:	58                   	pop    %rax
2c90     2c90:	fb                   	sti
2c91     2c91:	9c                   	pushf
2c92     2c92:	58                   	pop    %rax
2c93     2c93:	9c                   	pushf
2c94     2c94:	58                   	pop    %rax
2c95     2c95:	fb                   	sti
2c96     2c96:	9c                   	pushf
2c97     2c97:	58                   	pop    %rax
2c98     2c98:	fb                   	sti
2c99     2c99:	9c                   	pushf
2c9a     2c9a:	58                   	pop    %rax
2c9b     2c9b:	fa                   	cli
2c9c     2c9c:	9c                   	pushf
2c9d     2c9d:	58                   	pop    %rax
2c9e     2c9e:	fb                   	sti
2c9f     2c9f:	65 48 0f c7 0f       	cmpxchg16b %gs:(%rdi)
2ca4     2ca4:	0f 94 c0             	sete   %al
2ca7     2ca7:	0f 0d 0c 03          	prefetchw (%rbx,%rax,1)
2cab     2cab:	65 48 0f c7 0f       	cmpxchg16b %gs:(%rdi)
2cb0     2cb0:	0f 94 c0             	sete   %al
2cb3     2cb3:	0f 0d 0c 03          	prefetchw (%rbx,%rax,1)
2cb7     2cb7:	65 48 0f c7 0f       	cmpxchg16b %gs:(%rdi)
2cbc     2cbc:	0f 94 c0             	sete   %al
2cbf     2cbf:	0f 0d 0c 03          	prefetchw (%rbx,%rax,1)
2cc3     2cc3:	65 48 0f c7 0f       	cmpxchg16b %gs:(%rdi)
2cc8     2cc8:	0f 94 c0             	sete   %al
2ccb     2ccb:	65 48 0f c7 0f       	cmpxchg16b %gs:(%rdi)
2cd0     2cd0:	0f 94 c0             	sete   %al
2cd3     2cd3:	9c                   	pushf
2cd4     2cd4:	58                   	pop    %rax
2cd5     2cd5:	fa                   	cli
2cd6     2cd6:	fb                   	sti
2cd7     2cd7:	fb                   	sti
2cd8     2cd8:	9c                   	pushf
2cd9     2cd9:	58                   	pop    %rax
2cda     2cda:	fa                   	cli
2cdb     2cdb:	9c                   	pushf
2cdc     2cdc:	58                   	pop    %rax
2cdd     2cdd:	65 48 0f c7 0f       	cmpxchg16b %gs:(%rdi)
2ce2     2ce2:	0f 94 c0             	sete   %al
2ce5     2ce5:	0f 0d 0c 03          	prefetchw (%rbx,%rax,1)
2ce9     2ce9:	65 48 0f c7 0f       	cmpxchg16b %gs:(%rdi)
2cee     2cee:	0f 94 c0             	sete   %al
2cf1     2cf1:	65 48 0f c7 0f       	cmpxchg16b %gs:(%rdi)
2cf6     2cf6:	0f 94 c0             	sete   %al
2cf9     2cf9:	e9 00 00 00 00       	jmp    2cfe <.altinstr_replacement+0x2cfe>	2cfa: R_X86_64_PC32	.text.unlikely+0x7c4e8
2cfe     2cfe:	9c                   	pushf
2cff     2cff:	8f 04 24             	pop    (%rsp)
2d02     2d02:	0f 01 ca             	clac
2d05     2d05:	ff 34 24             	push   (%rsp)
2d08     2d08:	9d                   	popf
2d09     2d09:	48 89 f8             	mov    %rdi,%rax
2d0c     2d0c:	9c                   	pushf
2d0d     2d0d:	58                   	pop    %rax
2d0e     2d0e:	fa                   	cli
2d0f     2d0f:	9c                   	pushf
2d10     2d10:	58                   	pop    %rax
2d11     2d11:	fb                   	sti
2d12     2d12:	48 89 f8             	mov    %rdi,%rax
2d15     2d15:	48 89 f8             	mov    %rdi,%rax
2d18     2d18:	48 89 f8             	mov    %rdi,%rax
2d1b     2d1b:	48 89 f8             	mov    %rdi,%rax
2d1e     2d1e:	48 89 f8             	mov    %rdi,%rax
2d21     2d21:	48 89 f8             	mov    %rdi,%rax
2d24     2d24:	48 89 f8             	mov    %rdi,%rax
2d27     2d27:	48 89 f8             	mov    %rdi,%rax
2d2a     2d2a:	48 89 f8             	mov    %rdi,%rax
2d2d     2d2d:	48 89 f8             	mov    %rdi,%rax
2d30     2d30:	48 89 f8             	mov    %rdi,%rax
2d33     2d33:	48 89 f8             	mov    %rdi,%rax
2d36     2d36:	48 89 f8             	mov    %rdi,%rax
2d39     2d39:	48 89 f8             	mov    %rdi,%rax
2d3c     2d3c:	48 89 f8             	mov    %rdi,%rax
2d3f     2d3f:	48 89 f8             	mov    %rdi,%rax
2d42     2d42:	48 89 f8             	mov    %rdi,%rax
2d45     2d45:	48 89 f8             	mov    %rdi,%rax
2d48     2d48:	e9 00 00 00 00       	jmp    2d4d <.altinstr_replacement+0x2d4d>	2d49: R_X86_64_PC32	.text+0xb84702
2d4d     2d4d:	48 89 f8             	mov    %rdi,%rax
2d50     2d50:	48 89 f8             	mov    %rdi,%rax
2d53     2d53:	48 89 f8             	mov    %rdi,%rax
2d56     2d56:	48 89 f8             	mov    %rdi,%rax
2d59     2d59:	e9 00 00 00 00       	jmp    2d5e <.altinstr_replacement+0x2d5e>	2d5a: R_X86_64_PC32	.text+0xb847bc
2d5e     2d5e:	e9 00 00 00 00       	jmp    2d63 <.altinstr_replacement+0x2d63>	2d5f: R_X86_64_PC32	.text+0xb847d9
2d63     2d63:	48 89 f8             	mov    %rdi,%rax
2d66     2d66:	48 89 f8             	mov    %rdi,%rax
2d69     2d69:	48 89 f8             	mov    %rdi,%rax
2d6c     2d6c:	48 89 f8             	mov    %rdi,%rax
2d6f     2d6f:	48 89 f8             	mov    %rdi,%rax
2d72     2d72:	48 89 f8             	mov    %rdi,%rax
2d75     2d75:	48 89 f8             	mov    %rdi,%rax
2d78     2d78:	e9 00 00 00 00       	jmp    2d7d <.altinstr_replacement+0x2d7d>	2d79: R_X86_64_PC32	.text+0xb84b45
2d7d     2d7d:	e9 00 00 00 00       	jmp    2d82 <.altinstr_replacement+0x2d82>	2d7e: R_X86_64_PC32	.text+0xb84ae2
2d82     2d82:	e9 00 00 00 00       	jmp    2d87 <.altinstr_replacement+0x2d87>	2d83: R_X86_64_PC32	.text+0xb84b80
2d87     2d87:	e9 00 00 00 00       	jmp    2d8c <.altinstr_replacement+0x2d8c>	2d88: R_X86_64_PC32	.ref.text+0x62f3
2d8c     2d8c:	e9 00 00 00 00       	jmp    2d91 <.altinstr_replacement+0x2d91>	2d8d: R_X86_64_PC32	.ref.text+0x62df
2d91     2d91:	48 89 f8             	mov    %rdi,%rax
2d94     2d94:	48 89 f8             	mov    %rdi,%rax
2d97     2d97:	e9 00 00 00 00       	jmp    2d9c <.altinstr_replacement+0x2d9c>	2d98: R_X86_64_PC32	.text+0xb84cd3
2d9c     2d9c:	48 89 f8             	mov    %rdi,%rax
2d9f     2d9f:	e9 00 00 00 00       	jmp    2da4 <.altinstr_replacement+0x2da4>	2da0: R_X86_64_PC32	.text+0xb84ca5
2da4     2da4:	e9 00 00 00 00       	jmp    2da9 <.altinstr_replacement+0x2da9>	2da5: R_X86_64_PC32	.text+0xb84ddd
2da9     2da9:	e9 00 00 00 00       	jmp    2dae <.altinstr_replacement+0x2dae>	2daa: R_X86_64_PC32	.text+0xb850db
2dae     2dae:	e9 00 00 00 00       	jmp    2db3 <.altinstr_replacement+0x2db3>	2daf: R_X86_64_PC32	.text+0xb8515b
2db3     2db3:	e9 00 00 00 00       	jmp    2db8 <.altinstr_replacement+0x2db8>	2db4: R_X86_64_PC32	.text+0xb851db
2db8     2db8:	e9 00 00 00 00       	jmp    2dbd <.altinstr_replacement+0x2dbd>	2db9: R_X86_64_PC32	.text+0xb8529b
2dbd     2dbd:	e9 00 00 00 00       	jmp    2dc2 <.altinstr_replacement+0x2dc2>	2dbe: R_X86_64_PC32	.text+0xb8535b
2dc2     2dc2:	e9 00 00 00 00       	jmp    2dc7 <.altinstr_replacement+0x2dc7>	2dc3: R_X86_64_PC32	.text+0xb8541b
2dc7     2dc7:	e9 00 00 00 00       	jmp    2dcc <.altinstr_replacement+0x2dcc>	2dc8: R_X86_64_PC32	.text+0xb854db
2dcc     2dcc:	e9 00 00 00 00       	jmp    2dd1 <.altinstr_replacement+0x2dd1>	2dcd: R_X86_64_PC32	.text+0xb855db
2dd1     2dd1:	e9 00 00 00 00       	jmp    2dd6 <.altinstr_replacement+0x2dd6>	2dd2: R_X86_64_PC32	.text+0xb856db
2dd6     2dd6:	e9 00 00 00 00       	jmp    2ddb <.altinstr_replacement+0x2ddb>	2dd7: R_X86_64_PC32	.text+0xb8579b
2ddb     2ddb:	e9 00 00 00 00       	jmp    2de0 <.altinstr_replacement+0x2de0>	2ddc: R_X86_64_PC32	.text+0xb85b1d
2de0     2de0:	e9 00 00 00 00       	jmp    2de5 <.altinstr_replacement+0x2de5>	2de1: R_X86_64_PC32	.text+0xb864ce
2de5     2de5:	e9 00 00 00 00       	jmp    2dea <.altinstr_replacement+0x2dea>	2de6: R_X86_64_PC32	.text+0xb8666d
2dea     2dea:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
2df4     2df4:	e9 00 00 00 00       	jmp    2df9 <.altinstr_replacement+0x2df9>	2df5: R_X86_64_PC32	.text.unlikely+0x7cd50
2df9     2df9:	48 89 f8             	mov    %rdi,%rax
2dfc     2dfc:	e9 00 00 00 00       	jmp    2e01 <.altinstr_replacement+0x2e01>	2dfd: R_X86_64_PC32	.text.unlikely+0x7cd9e
2e01     2e01:	48 89 f8             	mov    %rdi,%rax
2e04     2e04:	48 89 f8             	mov    %rdi,%rax
2e07     2e07:	48 89 f8             	mov    %rdi,%rax
2e0a     2e0a:	48 89 f8             	mov    %rdi,%rax
2e0d     2e0d:	48 89 f8             	mov    %rdi,%rax
2e10     2e10:	9c                   	pushf
2e11     2e11:	58                   	pop    %rax
2e12     2e12:	fa                   	cli
2e13     2e13:	9c                   	pushf
2e14     2e14:	58                   	pop    %rax
2e15     2e15:	fb                   	sti
2e16     2e16:	9c                   	pushf
2e17     2e17:	58                   	pop    %rax
2e18     2e18:	fb                   	sti
2e19     2e19:	48 89 f8             	mov    %rdi,%rax
2e1c     2e1c:	48 89 f8             	mov    %rdi,%rax
2e1f     2e1f:	48 89 f8             	mov    %rdi,%rax
2e22     2e22:	48 89 f8             	mov    %rdi,%rax
2e25     2e25:	9c                   	pushf
2e26     2e26:	58                   	pop    %rax
2e27     2e27:	fa                   	cli
2e28     2e28:	9c                   	pushf
2e29     2e29:	58                   	pop    %rax
2e2a     2e2a:	fb                   	sti
2e2b     2e2b:	48 89 f8             	mov    %rdi,%rax
2e2e     2e2e:	48 89 f8             	mov    %rdi,%rax
2e31     2e31:	48 89 f8             	mov    %rdi,%rax
2e34     2e34:	e9 00 00 00 00       	jmp    2e39 <.altinstr_replacement+0x2e39>	2e35: R_X86_64_PC32	.text+0xb9996d
2e39     2e39:	e9 00 00 00 00       	jmp    2e3e <.altinstr_replacement+0x2e3e>	2e3a: R_X86_64_PC32	.text+0xb99b3a
2e3e     2e3e:	fb                   	sti
2e3f     2e3f:	48 89 f8             	mov    %rdi,%rax
2e42     2e42:	48 89 f8             	mov    %rdi,%rax
2e45     2e45:	48 89 f8             	mov    %rdi,%rax
2e48     2e48:	48 89 f8             	mov    %rdi,%rax
2e4b     2e4b:	48 89 f8             	mov    %rdi,%rax
2e4e     2e4e:	48 89 f8             	mov    %rdi,%rax
2e51     2e51:	e9 00 00 00 00       	jmp    2e56 <.altinstr_replacement+0x2e56>	2e52: R_X86_64_PC32	.text+0xba5939
2e56     2e56:	e9 00 00 00 00       	jmp    2e5b <.altinstr_replacement+0x2e5b>	2e57: R_X86_64_PC32	.text+0xba59d9
2e5b     2e5b:	48 89 f8             	mov    %rdi,%rax
2e5e     2e5e:	48 89 f8             	mov    %rdi,%rax
2e61     2e61:	e9 00 00 00 00       	jmp    2e66 <.altinstr_replacement+0x2e66>	2e62: R_X86_64_PC32	.text+0xba9173
2e66     2e66:	e9 00 00 00 00       	jmp    2e6b <.altinstr_replacement+0x2e6b>	2e67: R_X86_64_PC32	.text+0xba91cc
2e6b     2e6b:	48 89 f8             	mov    %rdi,%rax
2e6e     2e6e:	48 89 f8             	mov    %rdi,%rax
2e71     2e71:	48 89 f8             	mov    %rdi,%rax
2e74     2e74:	48 89 f8             	mov    %rdi,%rax
2e77     2e77:	48 89 f8             	mov    %rdi,%rax
2e7a     2e7a:	48 89 f8             	mov    %rdi,%rax
2e7d     2e7d:	48 89 f8             	mov    %rdi,%rax
2e80     2e80:	48 89 f8             	mov    %rdi,%rax
2e83     2e83:	48 89 f8             	mov    %rdi,%rax
2e86     2e86:	48 89 f8             	mov    %rdi,%rax
2e89     2e89:	48 89 f8             	mov    %rdi,%rax
2e8c     2e8c:	e9 00 00 00 00       	jmp    2e91 <.altinstr_replacement+0x2e91>	2e8d: R_X86_64_PC32	.text+0xbab792
2e91     2e91:	e9 00 00 00 00       	jmp    2e96 <.altinstr_replacement+0x2e96>	2e92: R_X86_64_PC32	.text+0xbab7a1
2e96     2e96:	48 89 f8             	mov    %rdi,%rax
2e99     2e99:	48 89 f8             	mov    %rdi,%rax
2e9c     2e9c:	48 89 f8             	mov    %rdi,%rax
2e9f     2e9f:	48 89 f8             	mov    %rdi,%rax
2ea2     2ea2:	48 89 f8             	mov    %rdi,%rax
2ea5     2ea5:	48 89 f8             	mov    %rdi,%rax
2ea8     2ea8:	48 89 f8             	mov    %rdi,%rax
2eab     2eab:	48 89 f8             	mov    %rdi,%rax
2eae     2eae:	48 89 f8             	mov    %rdi,%rax
2eb1     2eb1:	48 89 f8             	mov    %rdi,%rax
2eb4     2eb4:	48 89 f8             	mov    %rdi,%rax
2eb7     2eb7:	e9 00 00 00 00       	jmp    2ebc <.altinstr_replacement+0x2ebc>	2eb8: R_X86_64_PC32	.text+0xbaf32f
2ebc     2ebc:	e9 00 00 00 00       	jmp    2ec1 <.altinstr_replacement+0x2ec1>	2ebd: R_X86_64_PC32	.text+0xbaf388
2ec1     2ec1:	9c                   	pushf
2ec2     2ec2:	58                   	pop    %rax
2ec3     2ec3:	fa                   	cli
2ec4     2ec4:	9c                   	pushf
2ec5     2ec5:	58                   	pop    %rax
2ec6     2ec6:	fb                   	sti
2ec7     2ec7:	9c                   	pushf
2ec8     2ec8:	58                   	pop    %rax
2ec9     2ec9:	fa                   	cli
2eca     2eca:	9c                   	pushf
2ecb     2ecb:	58                   	pop    %rax
2ecc     2ecc:	fb                   	sti
2ecd     2ecd:	e9 00 00 00 00       	jmp    2ed2 <.altinstr_replacement+0x2ed2>	2ece: R_X86_64_PC32	.text+0xbb0c2b
2ed2     2ed2:	e9 00 00 00 00       	jmp    2ed7 <.altinstr_replacement+0x2ed7>	2ed3: R_X86_64_PC32	.text+0xbb0d6b
2ed7     2ed7:	48 89 f8             	mov    %rdi,%rax
2eda     2eda:	48 89 f8             	mov    %rdi,%rax
2edd     2edd:	48 89 f8             	mov    %rdi,%rax
2ee0     2ee0:	48 89 f8             	mov    %rdi,%rax
2ee3     2ee3:	48 89 f8             	mov    %rdi,%rax
2ee6     2ee6:	48 89 f8             	mov    %rdi,%rax
2ee9     2ee9:	48 89 f8             	mov    %rdi,%rax
2eec     2eec:	48 89 f8             	mov    %rdi,%rax
2eef     2eef:	48 89 f8             	mov    %rdi,%rax
2ef2     2ef2:	48 89 f8             	mov    %rdi,%rax
2ef5     2ef5:	48 89 f8             	mov    %rdi,%rax
2ef8     2ef8:	48 89 f8             	mov    %rdi,%rax
2efb     2efb:	48 89 f8             	mov    %rdi,%rax
2efe     2efe:	e9 00 00 00 00       	jmp    2f03 <.altinstr_replacement+0x2f03>	2eff: R_X86_64_PC32	.text+0xbb7ad2
2f03     2f03:	e9 00 00 00 00       	jmp    2f08 <.altinstr_replacement+0x2f08>	2f04: R_X86_64_PC32	.text+0xbb7ae1
2f08     2f08:	fb                   	sti
2f09     2f09:	48 89 f8             	mov    %rdi,%rax
2f0c     2f0c:	48 89 f8             	mov    %rdi,%rax
2f0f     2f0f:	48 89 f8             	mov    %rdi,%rax
2f12     2f12:	48 89 f8             	mov    %rdi,%rax
2f15     2f15:	48 89 f8             	mov    %rdi,%rax
2f18     2f18:	48 89 f8             	mov    %rdi,%rax
2f1b     2f1b:	48 89 f8             	mov    %rdi,%rax
2f1e     2f1e:	48 89 f8             	mov    %rdi,%rax
2f21     2f21:	48 89 f8             	mov    %rdi,%rax
2f24     2f24:	48 89 f8             	mov    %rdi,%rax
2f27     2f27:	48 89 f8             	mov    %rdi,%rax
2f2a     2f2a:	48 89 f8             	mov    %rdi,%rax
2f2d     2f2d:	48 89 f8             	mov    %rdi,%rax
2f30     2f30:	48 89 f8             	mov    %rdi,%rax
2f33     2f33:	48 89 f8             	mov    %rdi,%rax
2f36     2f36:	48 89 f8             	mov    %rdi,%rax
2f39     2f39:	48 89 f8             	mov    %rdi,%rax
2f3c     2f3c:	48 89 f8             	mov    %rdi,%rax
2f3f     2f3f:	48 89 f8             	mov    %rdi,%rax
2f42     2f42:	48 89 f8             	mov    %rdi,%rax
2f45     2f45:	9c                   	pushf
2f46     2f46:	58                   	pop    %rax
2f47     2f47:	fa                   	cli
2f48     2f48:	fb                   	sti
2f49     2f49:	48 89 f8             	mov    %rdi,%rax
2f4c     2f4c:	e9 00 00 00 00       	jmp    2f51 <.altinstr_replacement+0x2f51>	2f4d: R_X86_64_PC32	.text+0xbc6d52
2f51     2f51:	e9 00 00 00 00       	jmp    2f56 <.altinstr_replacement+0x2f56>	2f52: R_X86_64_PC32	.text+0xbc6d66
2f56     2f56:	e9 00 00 00 00       	jmp    2f5b <.altinstr_replacement+0x2f5b>	2f57: R_X86_64_PC32	.text+0xbc75ed
2f5b     2f5b:	e9 00 00 00 00       	jmp    2f60 <.altinstr_replacement+0x2f60>	2f5c: R_X86_64_PC32	.text+0xbc785e
2f60     2f60:	9c                   	pushf
2f61     2f61:	58                   	pop    %rax
2f62     2f62:	fa                   	cli
2f63     2f63:	9c                   	pushf
2f64     2f64:	58                   	pop    %rax
2f65     2f65:	fb                   	sti
2f66     2f66:	9c                   	pushf
2f67     2f67:	58                   	pop    %rax
2f68     2f68:	fa                   	cli
2f69     2f69:	9c                   	pushf
2f6a     2f6a:	58                   	pop    %rax
2f6b     2f6b:	fb                   	sti
2f6c     2f6c:	48 89 f8             	mov    %rdi,%rax
2f6f     2f6f:	48 89 f8             	mov    %rdi,%rax
2f72     2f72:	48 89 f8             	mov    %rdi,%rax
2f75     2f75:	48 89 f8             	mov    %rdi,%rax
2f78     2f78:	48 89 f8             	mov    %rdi,%rax
2f7b     2f7b:	48 89 f8             	mov    %rdi,%rax
2f7e     2f7e:	48 89 f8             	mov    %rdi,%rax
2f81     2f81:	e8 00 00 00 00       	call   2f86 <.altinstr_replacement+0x2f86>	2f82: R_X86_64_PLT32	clear_page_rep-0x4
2f86     2f86:	e8 00 00 00 00       	call   2f8b <.altinstr_replacement+0x2f8b>	2f87: R_X86_64_PLT32	clear_page_erms-0x4
2f8b     2f8b:	48 89 f8             	mov    %rdi,%rax
2f8e     2f8e:	48 89 f8             	mov    %rdi,%rax
2f91     2f91:	48 89 f8             	mov    %rdi,%rax
2f94     2f94:	48 89 f8             	mov    %rdi,%rax
2f97     2f97:	48 89 f8             	mov    %rdi,%rax
2f9a     2f9a:	48 89 f8             	mov    %rdi,%rax
2f9d     2f9d:	48 89 f8             	mov    %rdi,%rax
2fa0     2fa0:	48 89 f8             	mov    %rdi,%rax
2fa3     2fa3:	48 89 f8             	mov    %rdi,%rax
2fa6     2fa6:	48 89 f8             	mov    %rdi,%rax
2fa9     2fa9:	48 89 f8             	mov    %rdi,%rax
2fac     2fac:	e8 00 00 00 00       	call   2fb1 <.altinstr_replacement+0x2fb1>	2fad: R_X86_64_PLT32	clear_page_rep-0x4
2fb1     2fb1:	e8 00 00 00 00       	call   2fb6 <.altinstr_replacement+0x2fb6>	2fb2: R_X86_64_PLT32	clear_page_erms-0x4
2fb6     2fb6:	e8 00 00 00 00       	call   2fbb <.altinstr_replacement+0x2fbb>	2fb7: R_X86_64_PLT32	clear_page_rep-0x4
2fbb     2fbb:	e8 00 00 00 00       	call   2fc0 <.altinstr_replacement+0x2fc0>	2fbc: R_X86_64_PLT32	clear_page_erms-0x4
2fc0     2fc0:	48 89 f8             	mov    %rdi,%rax
2fc3     2fc3:	48 89 f8             	mov    %rdi,%rax
2fc6     2fc6:	48 89 f8             	mov    %rdi,%rax
2fc9     2fc9:	9c                   	pushf
2fca     2fca:	58                   	pop    %rax
2fcb     2fcb:	9c                   	pushf
2fcc     2fcc:	58                   	pop    %rax
2fcd     2fcd:	fa                   	cli
2fce     2fce:	9c                   	pushf
2fcf     2fcf:	58                   	pop    %rax
2fd0     2fd0:	fb                   	sti
2fd1     2fd1:	9c                   	pushf
2fd2     2fd2:	58                   	pop    %rax
2fd3     2fd3:	fa                   	cli
2fd4     2fd4:	9c                   	pushf
2fd5     2fd5:	58                   	pop    %rax
2fd6     2fd6:	fb                   	sti
2fd7     2fd7:	e9 00 00 00 00       	jmp    2fdc <.altinstr_replacement+0x2fdc>	2fd8: R_X86_64_PC32	.text+0xbdf76a
2fdc     2fdc:	e9 00 00 00 00       	jmp    2fe1 <.altinstr_replacement+0x2fe1>	2fdd: R_X86_64_PC32	.text+0xbdf7a0
2fe1     2fe1:	9c                   	pushf
2fe2     2fe2:	58                   	pop    %rax
2fe3     2fe3:	fa                   	cli
2fe4     2fe4:	9c                   	pushf
2fe5     2fe5:	58                   	pop    %rax
2fe6     2fe6:	fb                   	sti
2fe7     2fe7:	9c                   	pushf
2fe8     2fe8:	58                   	pop    %rax
2fe9     2fe9:	fa                   	cli
2fea     2fea:	9c                   	pushf
2feb     2feb:	58                   	pop    %rax
2fec     2fec:	fb                   	sti
2fed     2fed:	48 89 f8             	mov    %rdi,%rax
2ff0     2ff0:	48 89 f8             	mov    %rdi,%rax
2ff3     2ff3:	48 89 f8             	mov    %rdi,%rax
2ff6     2ff6:	48 89 f8             	mov    %rdi,%rax
2ff9     2ff9:	9c                   	pushf
2ffa     2ffa:	58                   	pop    %rax
2ffb     2ffb:	fa                   	cli
2ffc     2ffc:	9c                   	pushf
2ffd     2ffd:	58                   	pop    %rax
2ffe     2ffe:	fb                   	sti
2fff     2fff:	9c                   	pushf
3000     3000:	58                   	pop    %rax
3001     3001:	9c                   	pushf
3002     3002:	58                   	pop    %rax
3003     3003:	fa                   	cli
3004     3004:	9c                   	pushf
3005     3005:	58                   	pop    %rax
3006     3006:	fb                   	sti
3007     3007:	9c                   	pushf
3008     3008:	58                   	pop    %rax
3009     3009:	fa                   	cli
300a     300a:	9c                   	pushf
300b     300b:	58                   	pop    %rax
300c     300c:	fb                   	sti
300d     300d:	9c                   	pushf
300e     300e:	58                   	pop    %rax
300f     300f:	fa                   	cli
3010     3010:	9c                   	pushf
3011     3011:	58                   	pop    %rax
3012     3012:	fb                   	sti
3013     3013:	9c                   	pushf
3014     3014:	58                   	pop    %rax
3015     3015:	fa                   	cli
3016     3016:	9c                   	pushf
3017     3017:	58                   	pop    %rax
3018     3018:	fb                   	sti
3019     3019:	9c                   	pushf
301a     301a:	58                   	pop    %rax
301b     301b:	fa                   	cli
301c     301c:	9c                   	pushf
301d     301d:	58                   	pop    %rax
301e     301e:	fb                   	sti
301f     301f:	9c                   	pushf
3020     3020:	58                   	pop    %rax
3021     3021:	fa                   	cli
3022     3022:	fb                   	sti
3023     3023:	9c                   	pushf
3024     3024:	58                   	pop    %rax
3025     3025:	fa                   	cli
3026     3026:	fb                   	sti
3027     3027:	9c                   	pushf
3028     3028:	58                   	pop    %rax
3029     3029:	fa                   	cli
302a     302a:	9c                   	pushf
302b     302b:	58                   	pop    %rax
302c     302c:	fb                   	sti
302d     302d:	9c                   	pushf
302e     302e:	58                   	pop    %rax
302f     302f:	fa                   	cli
3030     3030:	9c                   	pushf
3031     3031:	58                   	pop    %rax
3032     3032:	fb                   	sti
3033     3033:	e9 00 00 00 00       	jmp    3038 <.altinstr_replacement+0x3038>	3034: R_X86_64_PC32	.text+0xbfdb1e
3038     3038:	48 89 f8             	mov    %rdi,%rax
303b     303b:	e9 00 00 00 00       	jmp    3040 <.altinstr_replacement+0x3040>	303c: R_X86_64_PC32	.text+0xbfdbad
3040     3040:	e9 00 00 00 00       	jmp    3045 <.altinstr_replacement+0x3045>	3041: R_X86_64_PC32	.text+0xbfdc03
3045     3045:	48 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbp
304f     304f:	48 89 f8             	mov    %rdi,%rax
3052     3052:	48 89 f8             	mov    %rdi,%rax
3055     3055:	48 89 f8             	mov    %rdi,%rax
3058     3058:	48 89 f8             	mov    %rdi,%rax
305b     305b:	48 89 f8             	mov    %rdi,%rax
305e     305e:	48 89 f8             	mov    %rdi,%rax
3061     3061:	48 89 f8             	mov    %rdi,%rax
3064     3064:	48 89 f8             	mov    %rdi,%rax
3067     3067:	e9 00 00 00 00       	jmp    306c <.altinstr_replacement+0x306c>	3068: R_X86_64_PC32	.text+0xc01e2d
306c     306c:	48 89 f8             	mov    %rdi,%rax
306f     306f:	48 89 f8             	mov    %rdi,%rax
3072     3072:	48 89 f8             	mov    %rdi,%rax
3075     3075:	48 89 f8             	mov    %rdi,%rax
3078     3078:	48 89 f8             	mov    %rdi,%rax
307b     307b:	e9 00 00 00 00       	jmp    3080 <.altinstr_replacement+0x3080>	307c: R_X86_64_PC32	.text+0xc06726
3080     3080:	e9 00 00 00 00       	jmp    3085 <.altinstr_replacement+0x3085>	3081: R_X86_64_PC32	.text+0xc06610
3085     3085:	e9 00 00 00 00       	jmp    308a <.altinstr_replacement+0x308a>	3086: R_X86_64_PC32	.text+0xc0a798
308a     308a:	e9 00 00 00 00       	jmp    308f <.altinstr_replacement+0x308f>	308b: R_X86_64_PC32	.text+0xc0aa11
308f     308f:	e9 00 00 00 00       	jmp    3094 <.altinstr_replacement+0x3094>	3090: R_X86_64_PC32	.text+0xc0b42b
3094     3094:	e9 00 00 00 00       	jmp    3099 <.altinstr_replacement+0x3099>	3095: R_X86_64_PC32	.text+0xc0b810
3099     3099:	e9 00 00 00 00       	jmp    309e <.altinstr_replacement+0x309e>	309a: R_X86_64_PC32	.text+0xc0b5d1
309e     309e:	e9 00 00 00 00       	jmp    30a3 <.altinstr_replacement+0x30a3>	309f: R_X86_64_PC32	.text+0xc0b5d8
30a3     30a3:	e9 00 00 00 00       	jmp    30a8 <.altinstr_replacement+0x30a8>	30a4: R_X86_64_PC32	.text+0xc0bf86
30a8     30a8:	e9 00 00 00 00       	jmp    30ad <.altinstr_replacement+0x30ad>	30a9: R_X86_64_PC32	.text+0xc0be71
30ad     30ad:	e9 00 00 00 00       	jmp    30b2 <.altinstr_replacement+0x30b2>	30ae: R_X86_64_PC32	.text.unlikely+0x84302
30b2     30b2:	48 89 f8             	mov    %rdi,%rax
30b5     30b5:	e9 00 00 00 00       	jmp    30ba <.altinstr_replacement+0x30ba>	30b6: R_X86_64_PC32	.text.unlikely+0x8475e
30ba     30ba:	48 89 f8             	mov    %rdi,%rax
30bd     30bd:	48 89 f8             	mov    %rdi,%rax
30c0     30c0:	48 89 f8             	mov    %rdi,%rax
30c3     30c3:	48 89 f8             	mov    %rdi,%rax
30c6     30c6:	48 89 f8             	mov    %rdi,%rax
30c9     30c9:	48 89 f8             	mov    %rdi,%rax
30cc     30cc:	48 89 f8             	mov    %rdi,%rax
30cf     30cf:	48 89 f8             	mov    %rdi,%rax
30d2     30d2:	48 89 f8             	mov    %rdi,%rax
30d5     30d5:	e9 00 00 00 00       	jmp    30da <.altinstr_replacement+0x30da>	30d6: R_X86_64_PC32	.text.unlikely+0x853fc
30da     30da:	e9 00 00 00 00       	jmp    30df <.altinstr_replacement+0x30df>	30db: R_X86_64_PC32	.text.unlikely+0x853c2
30df     30df:	9c                   	pushf
30e0     30e0:	58                   	pop    %rax
30e1     30e1:	fa                   	cli
30e2     30e2:	9c                   	pushf
30e3     30e3:	58                   	pop    %rax
30e4     30e4:	fb                   	sti
30e5     30e5:	e9 00 00 00 00       	jmp    30ea <.altinstr_replacement+0x30ea>	30e6: R_X86_64_PC32	.init.text+0xf18da
30ea     30ea:	e9 00 00 00 00       	jmp    30ef <.altinstr_replacement+0x30ef>	30eb: R_X86_64_PC32	.text.unlikely+0x85c88
30ef     30ef:	e9 00 00 00 00       	jmp    30f4 <.altinstr_replacement+0x30f4>	30f0: R_X86_64_PC32	.init.text+0xf2193
30f4     30f4:	e9 00 00 00 00       	jmp    30f9 <.altinstr_replacement+0x30f9>	30f5: R_X86_64_PC32	.init.text+0xf21d8
30f9     30f9:	e9 00 00 00 00       	jmp    30fe <.altinstr_replacement+0x30fe>	30fa: R_X86_64_PC32	.init.text+0xf2259
30fe     30fe:	e9 00 00 00 00       	jmp    3103 <.altinstr_replacement+0x3103>	30ff: R_X86_64_PC32	.init.text+0xf240b
3103     3103:	e9 00 00 00 00       	jmp    3108 <.altinstr_replacement+0x3108>	3104: R_X86_64_PC32	.init.text+0xf2450
3108     3108:	e9 00 00 00 00       	jmp    310d <.altinstr_replacement+0x310d>	3109: R_X86_64_PC32	.text.unlikely+0x85ce9
310d     310d:	e9 00 00 00 00       	jmp    3112 <.altinstr_replacement+0x3112>	310e: R_X86_64_PC32	.text.unlikely+0x85d35
3112     3112:	49 bf 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r15
311c     311c:	e9 00 00 00 00       	jmp    3121 <.altinstr_replacement+0x3121>	311d: R_X86_64_PC32	.text+0xc10a9c
3121     3121:	e9 00 00 00 00       	jmp    3126 <.altinstr_replacement+0x3126>	3122: R_X86_64_PC32	.text+0xc10ae2
3126     3126:	e9 00 00 00 00       	jmp    312b <.altinstr_replacement+0x312b>	3127: R_X86_64_PC32	.text+0xc1132c
312b     312b:	e9 00 00 00 00       	jmp    3130 <.altinstr_replacement+0x3130>	312c: R_X86_64_PC32	.text+0xc11340
3130     3130:	e9 00 00 00 00       	jmp    3135 <.altinstr_replacement+0x3135>	3131: R_X86_64_PC32	.text+0xc11336
3135     3135:	e9 00 00 00 00       	jmp    313a <.altinstr_replacement+0x313a>	3136: R_X86_64_PC32	.text+0xc11356
313a     313a:	e9 00 00 00 00       	jmp    313f <.altinstr_replacement+0x313f>	313b: R_X86_64_PC32	.text.unlikely+0x86dc7
313f     313f:	e9 00 00 00 00       	jmp    3144 <.altinstr_replacement+0x3144>	3140: R_X86_64_PC32	.text.unlikely+0x86e0b
3144     3144:	e9 00 00 00 00       	jmp    3149 <.altinstr_replacement+0x3149>	3145: R_X86_64_PC32	.text+0xc2c58a
3149     3149:	e9 00 00 00 00       	jmp    314e <.altinstr_replacement+0x314e>	314a: R_X86_64_PC32	.text.unlikely+0x8739d
314e     314e:	e9 00 00 00 00       	jmp    3153 <.altinstr_replacement+0x3153>	314f: R_X86_64_PC32	.text+0xc2c777
3153     3153:	e9 00 00 00 00       	jmp    3158 <.altinstr_replacement+0x3158>	3154: R_X86_64_PC32	.text+0xc2cc31
3158     3158:	e9 00 00 00 00       	jmp    315d <.altinstr_replacement+0x315d>	3159: R_X86_64_PC32	.text+0xc2ca14
315d     315d:	e9 00 00 00 00       	jmp    3162 <.altinstr_replacement+0x3162>	315e: R_X86_64_PC32	.text+0xc2d0a9
3162     3162:	e9 00 00 00 00       	jmp    3167 <.altinstr_replacement+0x3167>	3163: R_X86_64_PC32	.text+0xc2ce90
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
31a6     31a6:	e9 00 00 00 00       	jmp    31ab <.altinstr_replacement+0x31ab>	31a7: R_X86_64_PC32	.text+0xc2f252
31ab     31ab:	e9 00 00 00 00       	jmp    31b0 <.altinstr_replacement+0x31b0>	31ac: R_X86_64_PC32	.text+0xc2f2eb
31b0     31b0:	48 89 f8             	mov    %rdi,%rax
31b3     31b3:	48 89 f8             	mov    %rdi,%rax
31b6     31b6:	48 89 f8             	mov    %rdi,%rax
31b9     31b9:	48 89 f8             	mov    %rdi,%rax
31bc     31bc:	48 89 f8             	mov    %rdi,%rax
31bf     31bf:	48 89 f8             	mov    %rdi,%rax
31c2     31c2:	48 89 f8             	mov    %rdi,%rax
31c5     31c5:	48 89 f8             	mov    %rdi,%rax
31c8     31c8:	48 89 f8             	mov    %rdi,%rax
31cb     31cb:	48 89 f8             	mov    %rdi,%rax
31ce     31ce:	48 89 f8             	mov    %rdi,%rax
31d1     31d1:	48 89 f8             	mov    %rdi,%rax
31d4     31d4:	48 89 f8             	mov    %rdi,%rax
31d7     31d7:	48 89 f8             	mov    %rdi,%rax
31da     31da:	48 89 f8             	mov    %rdi,%rax
31dd     31dd:	48 89 f8             	mov    %rdi,%rax
31e0     31e0:	48 89 f8             	mov    %rdi,%rax
31e3     31e3:	48 89 f8             	mov    %rdi,%rax
31e6     31e6:	48 89 f8             	mov    %rdi,%rax
31e9     31e9:	48 89 f8             	mov    %rdi,%rax
31ec     31ec:	48 89 f8             	mov    %rdi,%rax
31ef     31ef:	48 89 f8             	mov    %rdi,%rax
31f2     31f2:	48 89 f8             	mov    %rdi,%rax
31f5     31f5:	48 89 f8             	mov    %rdi,%rax
31f8     31f8:	48 89 f8             	mov    %rdi,%rax
31fb     31fb:	48 89 f8             	mov    %rdi,%rax
31fe     31fe:	48 89 f8             	mov    %rdi,%rax
3201     3201:	48 89 f8             	mov    %rdi,%rax
3204     3204:	48 89 f8             	mov    %rdi,%rax
3207     3207:	48 89 f8             	mov    %rdi,%rax
320a     320a:	48 89 f8             	mov    %rdi,%rax
320d     320d:	48 89 f8             	mov    %rdi,%rax
3210     3210:	48 89 f8             	mov    %rdi,%rax
3213     3213:	e9 00 00 00 00       	jmp    3218 <.altinstr_replacement+0x3218>	3214: R_X86_64_PC32	.text+0xc5c12d
3218     3218:	e9 00 00 00 00       	jmp    321d <.altinstr_replacement+0x321d>	3219: R_X86_64_PC32	.text+0xc5c183
321d     321d:	48 89 f8             	mov    %rdi,%rax
3220     3220:	48 89 f8             	mov    %rdi,%rax
3223     3223:	48 89 f8             	mov    %rdi,%rax
3226     3226:	48 89 f8             	mov    %rdi,%rax
3229     3229:	48 89 f8             	mov    %rdi,%rax
322c     322c:	48 89 f8             	mov    %rdi,%rax
322f     322f:	48 89 f8             	mov    %rdi,%rax
3232     3232:	48 89 f8             	mov    %rdi,%rax
3235     3235:	48 89 f8             	mov    %rdi,%rax
3238     3238:	48 89 f8             	mov    %rdi,%rax
323b     323b:	48 89 f8             	mov    %rdi,%rax
323e     323e:	48 89 f8             	mov    %rdi,%rax
3241     3241:	48 89 f8             	mov    %rdi,%rax
3244     3244:	48 89 f8             	mov    %rdi,%rax
3247     3247:	48 89 f8             	mov    %rdi,%rax
324a     324a:	48 89 f8             	mov    %rdi,%rax
324d     324d:	48 89 f8             	mov    %rdi,%rax
3250     3250:	48 89 f8             	mov    %rdi,%rax
3253     3253:	48 89 f8             	mov    %rdi,%rax
3256     3256:	48 89 f8             	mov    %rdi,%rax
3259     3259:	48 89 f8             	mov    %rdi,%rax
325c     325c:	48 89 f8             	mov    %rdi,%rax
325f     325f:	48 89 f8             	mov    %rdi,%rax
3262     3262:	48 89 f8             	mov    %rdi,%rax
3265     3265:	48 89 f8             	mov    %rdi,%rax
3268     3268:	48 89 f8             	mov    %rdi,%rax
326b     326b:	48 89 f8             	mov    %rdi,%rax
326e     326e:	48 89 f8             	mov    %rdi,%rax
3271     3271:	48 89 f8             	mov    %rdi,%rax
3274     3274:	48 89 f8             	mov    %rdi,%rax
3277     3277:	48 89 f8             	mov    %rdi,%rax
327a     327a:	48 89 f8             	mov    %rdi,%rax
327d     327d:	48 89 f8             	mov    %rdi,%rax
3280     3280:	48 89 f8             	mov    %rdi,%rax
3283     3283:	48 89 f8             	mov    %rdi,%rax
3286     3286:	48 89 f8             	mov    %rdi,%rax
3289     3289:	48 89 f8             	mov    %rdi,%rax
328c     328c:	48 89 f8             	mov    %rdi,%rax
328f     328f:	48 89 f8             	mov    %rdi,%rax
3292     3292:	48 89 f8             	mov    %rdi,%rax
3295     3295:	e9 00 00 00 00       	jmp    329a <.altinstr_replacement+0x329a>	3296: R_X86_64_PC32	.text.unlikely+0x8805f
329a     329a:	e9 00 00 00 00       	jmp    329f <.altinstr_replacement+0x329f>	329b: R_X86_64_PC32	.init.text+0xfa0ac
329f     329f:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
32a9     32a9:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
32b3     32b3:	48 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbp
32bd     32bd:	9c                   	pushf
32be     32be:	58                   	pop    %rax
32bf     32bf:	fa                   	cli
32c0     32c0:	fb                   	sti
32c1     32c1:	49 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r13
32cb     32cb:	9c                   	pushf
32cc     32cc:	58                   	pop    %rax
32cd     32cd:	fa                   	cli
32ce     32ce:	9c                   	pushf
32cf     32cf:	58                   	pop    %rax
32d0     32d0:	fb                   	sti
32d1     32d1:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
32db     32db:	0f 01 cb             	stac
32de     32de:	0f ae e8             	lfence
32e1     32e1:	0f 01 ca             	clac
32e4     32e4:	0f 01 ca             	clac
32e7     32e7:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
32f1     32f1:	0f 01 cb             	stac
32f4     32f4:	0f ae e8             	lfence
32f7     32f7:	0f 01 ca             	clac
32fa     32fa:	0f 01 ca             	clac
32fd     32fd:	49 bf 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r15
3307     3307:	0f 01 cb             	stac
330a     330a:	0f ae e8             	lfence
330d     330d:	0f 01 ca             	clac
3310     3310:	0f 01 ca             	clac
3313     3313:	49 bf 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r15
331d     331d:	0f 01 cb             	stac
3320     3320:	0f ae e8             	lfence
3323     3323:	0f 01 ca             	clac
3326     3326:	0f 01 ca             	clac
3329     3329:	49 bf 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r15
3333     3333:	0f 01 cb             	stac
3336     3336:	0f ae e8             	lfence
3339     3339:	0f 01 ca             	clac
333c     333c:	0f 01 ca             	clac
333f     333f:	0f 01 ca             	clac
3342     3342:	49 bf 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r15
334c     334c:	0f 01 cb             	stac
334f     334f:	0f ae e8             	lfence
3352     3352:	0f 01 ca             	clac
3355     3355:	48 ba 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rdx
335f     335f:	0f 01 cb             	stac
3362     3362:	0f ae e8             	lfence
3365     3365:	0f 01 ca             	clac
3368     3368:	0f 01 ca             	clac
336b     336b:	48 ba 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rdx
3375     3375:	0f 01 cb             	stac
3378     3378:	0f ae e8             	lfence
337b     337b:	0f 01 ca             	clac
337e     337e:	0f 01 ca             	clac
3381     3381:	48 ba 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rdx
338b     338b:	0f 01 cb             	stac
338e     338e:	0f ae e8             	lfence
3391     3391:	0f 01 ca             	clac
3394     3394:	0f 01 ca             	clac
3397     3397:	48 ba 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rdx
33a1     33a1:	0f 01 cb             	stac
33a4     33a4:	0f ae e8             	lfence
33a7     33a7:	0f 01 ca             	clac
33aa     33aa:	0f 01 ca             	clac
33ad     33ad:	e8 00 00 00 00       	call   33b2 <.altinstr_replacement+0x33b2>	33ae: R_X86_64_PLT32	copy_user_generic_string-0x4
33b2     33b2:	e8 00 00 00 00       	call   33b7 <.altinstr_replacement+0x33b7>	33b3: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
33b7     33b7:	e8 00 00 00 00       	call   33bc <.altinstr_replacement+0x33bc>	33b8: R_X86_64_PLT32	copy_user_generic_string-0x4
33bc     33bc:	e8 00 00 00 00       	call   33c1 <.altinstr_replacement+0x33c1>	33bd: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
33c1     33c1:	e8 00 00 00 00       	call   33c6 <.altinstr_replacement+0x33c6>	33c2: R_X86_64_PLT32	copy_user_generic_string-0x4
33c6     33c6:	e8 00 00 00 00       	call   33cb <.altinstr_replacement+0x33cb>	33c7: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
33cb     33cb:	48 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbp
33d5     33d5:	0f 01 cb             	stac
33d8     33d8:	0f ae e8             	lfence
33db     33db:	0f 01 ca             	clac
33de     33de:	0f 01 ca             	clac
33e1     33e1:	48 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbp
33eb     33eb:	0f 01 cb             	stac
33ee     33ee:	0f ae e8             	lfence
33f1     33f1:	0f 01 ca             	clac
33f4     33f4:	0f 01 ca             	clac
33f7     33f7:	9c                   	pushf
33f8     33f8:	58                   	pop    %rax
33f9     33f9:	fa                   	cli
33fa     33fa:	9c                   	pushf
33fb     33fb:	58                   	pop    %rax
33fc     33fc:	fb                   	sti
33fd     33fd:	41 0f 0d 8c 24 00 03 00 00 	prefetchw 0x300(%r12)
3406     3406:	9c                   	pushf
3407     3407:	58                   	pop    %rax
3408     3408:	fa                   	cli
3409     3409:	9c                   	pushf
340a     340a:	58                   	pop    %rax
340b     340b:	fb                   	sti
340c     340c:	f3 0f b8 c7          	popcnt %edi,%eax
3410     3410:	f3 0f b8 c7          	popcnt %edi,%eax
3414     3414:	9c                   	pushf
3415     3415:	58                   	pop    %rax
3416     3416:	fa                   	cli
3417     3417:	9c                   	pushf
3418     3418:	58                   	pop    %rax
3419     3419:	fb                   	sti
341a     341a:	9c                   	pushf
341b     341b:	58                   	pop    %rax
341c     341c:	9c                   	pushf
341d     341d:	58                   	pop    %rax
341e     341e:	fa                   	cli
341f     341f:	fb                   	sti
3420     3420:	9c                   	pushf
3421     3421:	58                   	pop    %rax
3422     3422:	9c                   	pushf
3423     3423:	58                   	pop    %rax
3424     3424:	fa                   	cli
3425     3425:	fb                   	sti
3426     3426:	fb                   	sti
3427     3427:	9c                   	pushf
3428     3428:	58                   	pop    %rax
3429     3429:	fa                   	cli
342a     342a:	fb                   	sti
342b     342b:	41 0f 0d 0c 24       	prefetchw (%r12)
3430     3430:	48 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbp
343a     343a:	0f 01 cb             	stac
343d     343d:	e8 00 00 00 00       	call   3442 <.altinstr_replacement+0x3442>	343e: R_X86_64_PLT32	clear_user_erms-0x4
3442     3442:	e8 00 00 00 00       	call   3447 <.altinstr_replacement+0x3447>	3443: R_X86_64_PLT32	clear_user_rep_good-0x4
3447     3447:	e8 00 00 00 00       	call   344c <.altinstr_replacement+0x344c>	3448: R_X86_64_PLT32	clear_user_original-0x4
344c     344c:	0f 01 ca             	clac
344f     344f:	48 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbp
3459     3459:	0f 01 cb             	stac
345c     345c:	e8 00 00 00 00       	call   3461 <.altinstr_replacement+0x3461>	345d: R_X86_64_PLT32	clear_user_erms-0x4
3461     3461:	e8 00 00 00 00       	call   3466 <.altinstr_replacement+0x3466>	3462: R_X86_64_PLT32	clear_user_rep_good-0x4
3466     3466:	e8 00 00 00 00       	call   346b <.altinstr_replacement+0x346b>	3467: R_X86_64_PLT32	clear_user_original-0x4
346b     346b:	0f 01 ca             	clac
346e     346e:	49 bf 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r15
3478     3478:	e9 00 00 00 00       	jmp    347d <.altinstr_replacement+0x347d>	3479: R_X86_64_PC32	.text+0xd70d5e
347d     347d:	48 89 f8             	mov    %rdi,%rax
3480     3480:	9c                   	pushf
3481     3481:	58                   	pop    %rax
3482     3482:	fa                   	cli
3483     3483:	9c                   	pushf
3484     3484:	58                   	pop    %rax
3485     3485:	fb                   	sti
3486     3486:	48 89 f8             	mov    %rdi,%rax
3489     3489:	48 89 f8             	mov    %rdi,%rax
348c     348c:	e9 00 00 00 00       	jmp    3491 <.altinstr_replacement+0x3491>	348d: R_X86_64_PC32	.text+0xd76269
3491     3491:	48 89 f8             	mov    %rdi,%rax
3494     3494:	48 89 f8             	mov    %rdi,%rax
3497     3497:	48 89 f8             	mov    %rdi,%rax
349a     349a:	48 89 f8             	mov    %rdi,%rax
349d     349d:	9c                   	pushf
349e     349e:	58                   	pop    %rax
349f     349f:	fa                   	cli
34a0     34a0:	9c                   	pushf
34a1     34a1:	58                   	pop    %rax
34a2     34a2:	fb                   	sti
34a3     34a3:	9c                   	pushf
34a4     34a4:	58                   	pop    %rax
34a5     34a5:	fa                   	cli
34a6     34a6:	9c                   	pushf
34a7     34a7:	58                   	pop    %rax
34a8     34a8:	fb                   	sti
34a9     34a9:	9c                   	pushf
34aa     34aa:	58                   	pop    %rax
34ab     34ab:	fa                   	cli
34ac     34ac:	9c                   	pushf
34ad     34ad:	58                   	pop    %rax
34ae     34ae:	fb                   	sti
34af     34af:	9c                   	pushf
34b0     34b0:	58                   	pop    %rax
34b1     34b1:	fa                   	cli
34b2     34b2:	9c                   	pushf
34b3     34b3:	58                   	pop    %rax
34b4     34b4:	fb                   	sti
34b5     34b5:	e8 00 00 00 00       	call   34ba <.altinstr_replacement+0x34ba>	34b6: R_X86_64_PLT32	clear_page_rep-0x4
34ba     34ba:	e8 00 00 00 00       	call   34bf <.altinstr_replacement+0x34bf>	34bb: R_X86_64_PLT32	clear_page_erms-0x4
34bf     34bf:	48 89 f8             	mov    %rdi,%rax
34c2     34c2:	48 89 f8             	mov    %rdi,%rax
34c5     34c5:	48 89 f8             	mov    %rdi,%rax
34c8     34c8:	48 89 f8             	mov    %rdi,%rax
34cb     34cb:	48 89 f8             	mov    %rdi,%rax
34ce     34ce:	48 89 f8             	mov    %rdi,%rax
34d1     34d1:	48 89 f8             	mov    %rdi,%rax
34d4     34d4:	49 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r13
34de     34de:	0f 01 cb             	stac
34e1     34e1:	e8 00 00 00 00       	call   34e6 <.altinstr_replacement+0x34e6>	34e2: R_X86_64_PLT32	clear_user_erms-0x4
34e6     34e6:	e8 00 00 00 00       	call   34eb <.altinstr_replacement+0x34eb>	34e7: R_X86_64_PLT32	clear_user_rep_good-0x4
34eb     34eb:	e8 00 00 00 00       	call   34f0 <.altinstr_replacement+0x34f0>	34ec: R_X86_64_PLT32	clear_user_original-0x4
34f0     34f0:	0f 01 ca             	clac
34f3     34f3:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
34fd     34fd:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
3507     3507:	48 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbp
3511     3511:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
351b     351b:	48 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbp
3525     3525:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
352f     352f:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
3539     3539:	49 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r13
3543     3543:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
354d     354d:	49 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r13
3557     3557:	0f 01 cb             	stac
355a     355a:	e8 00 00 00 00       	call   355f <.altinstr_replacement+0x355f>	355b: R_X86_64_PLT32	clear_user_erms-0x4
355f     355f:	e8 00 00 00 00       	call   3564 <.altinstr_replacement+0x3564>	3560: R_X86_64_PLT32	clear_user_rep_good-0x4
3564     3564:	e8 00 00 00 00       	call   3569 <.altinstr_replacement+0x3569>	3565: R_X86_64_PLT32	clear_user_original-0x4
3569     3569:	0f 01 ca             	clac
356c     356c:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
3576     3576:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
3580     3580:	49 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r13
358a     358a:	0f 01 cb             	stac
358d     358d:	e8 00 00 00 00       	call   3592 <.altinstr_replacement+0x3592>	358e: R_X86_64_PLT32	clear_user_erms-0x4
3592     3592:	e8 00 00 00 00       	call   3597 <.altinstr_replacement+0x3597>	3593: R_X86_64_PLT32	clear_user_rep_good-0x4
3597     3597:	e8 00 00 00 00       	call   359c <.altinstr_replacement+0x359c>	3598: R_X86_64_PLT32	clear_user_original-0x4
359c     359c:	0f 01 ca             	clac
359f     359f:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
35a9     35a9:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
35b3     35b3:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
35bd     35bd:	48 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbp
35c7     35c7:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
35d1     35d1:	49 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r13
35db     35db:	48 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbp
35e5     35e5:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
35ef     35ef:	48 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbp
35f9     35f9:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
3603     3603:	0f 01 cb             	stac
3606     3606:	e8 00 00 00 00       	call   360b <.altinstr_replacement+0x360b>	3607: R_X86_64_PLT32	clear_user_erms-0x4
360b     360b:	e8 00 00 00 00       	call   3610 <.altinstr_replacement+0x3610>	360c: R_X86_64_PLT32	clear_user_rep_good-0x4
3610     3610:	e8 00 00 00 00       	call   3615 <.altinstr_replacement+0x3615>	3611: R_X86_64_PLT32	clear_user_original-0x4
3615     3615:	0f 01 ca             	clac
3618     3618:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
3622     3622:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
362c     362c:	e9 00 00 00 00       	jmp    3631 <.altinstr_replacement+0x3631>	362d: R_X86_64_PC32	.text+0xe02433
3631     3631:	48 89 f8             	mov    %rdi,%rax
3634     3634:	e9 00 00 00 00       	jmp    3639 <.altinstr_replacement+0x3639>	3635: R_X86_64_PC32	.text+0xe0546d
3639     3639:	e9 00 00 00 00       	jmp    363e <.altinstr_replacement+0x363e>	363a: R_X86_64_PC32	.text+0xe054c3
363e     363e:	48 89 f8             	mov    %rdi,%rax
3641     3641:	48 89 f8             	mov    %rdi,%rax
3644     3644:	48 89 f8             	mov    %rdi,%rax
3647     3647:	48 89 f8             	mov    %rdi,%rax
364a     364a:	48 89 f8             	mov    %rdi,%rax
364d     364d:	48 89 f8             	mov    %rdi,%rax
3650     3650:	48 89 f8             	mov    %rdi,%rax
3653     3653:	48 89 f8             	mov    %rdi,%rax
3656     3656:	48 89 f8             	mov    %rdi,%rax
3659     3659:	48 89 f8             	mov    %rdi,%rax
365c     365c:	48 89 f8             	mov    %rdi,%rax
365f     365f:	e9 00 00 00 00       	jmp    3664 <.altinstr_replacement+0x3664>	3660: R_X86_64_PC32	.text+0xe087b3
3664     3664:	e9 00 00 00 00       	jmp    3669 <.altinstr_replacement+0x3669>	3665: R_X86_64_PC32	.text+0xe0880c
3669     3669:	48 89 f8             	mov    %rdi,%rax
366c     366c:	e9 00 00 00 00       	jmp    3671 <.altinstr_replacement+0x3671>	366d: R_X86_64_PC32	.text+0xe08d5a
3671     3671:	48 89 f8             	mov    %rdi,%rax
3674     3674:	e9 00 00 00 00       	jmp    3679 <.altinstr_replacement+0x3679>	3675: R_X86_64_PC32	.text+0xe09410
3679     3679:	48 89 f8             	mov    %rdi,%rax
367c     367c:	e9 00 00 00 00       	jmp    3681 <.altinstr_replacement+0x3681>	367d: R_X86_64_PC32	.text+0xe09669
3681     3681:	48 89 f8             	mov    %rdi,%rax
3684     3684:	48 89 f8             	mov    %rdi,%rax
3687     3687:	48 89 f8             	mov    %rdi,%rax
368a     368a:	48 89 f8             	mov    %rdi,%rax
368d     368d:	48 89 f8             	mov    %rdi,%rax
3690     3690:	48 89 f8             	mov    %rdi,%rax
3693     3693:	e9 00 00 00 00       	jmp    3698 <.altinstr_replacement+0x3698>	3694: R_X86_64_PC32	.text+0xe0a53a
3698     3698:	48 89 f8             	mov    %rdi,%rax
369b     369b:	48 89 f8             	mov    %rdi,%rax
369e     369e:	48 89 f8             	mov    %rdi,%rax
36a1     36a1:	48 89 f8             	mov    %rdi,%rax
36a4     36a4:	48 89 f8             	mov    %rdi,%rax
36a7     36a7:	48 89 f8             	mov    %rdi,%rax
36aa     36aa:	48 89 f8             	mov    %rdi,%rax
36ad     36ad:	e9 00 00 00 00       	jmp    36b2 <.altinstr_replacement+0x36b2>	36ae: R_X86_64_PC32	.text+0xe0cdeb
36b2     36b2:	48 89 f8             	mov    %rdi,%rax
36b5     36b5:	48 89 f8             	mov    %rdi,%rax
36b8     36b8:	48 89 f8             	mov    %rdi,%rax
36bb     36bb:	48 89 f8             	mov    %rdi,%rax
36be     36be:	48 89 f8             	mov    %rdi,%rax
36c1     36c1:	e9 00 00 00 00       	jmp    36c6 <.altinstr_replacement+0x36c6>	36c2: R_X86_64_PC32	.text+0xe2d36d
36c6     36c6:	e9 00 00 00 00       	jmp    36cb <.altinstr_replacement+0x36cb>	36c7: R_X86_64_PC32	.text+0xe37f2e
36cb     36cb:	e9 00 00 00 00       	jmp    36d0 <.altinstr_replacement+0x36d0>	36cc: R_X86_64_PC32	.text+0xe38bd6
36d0     36d0:	e9 00 00 00 00       	jmp    36d5 <.altinstr_replacement+0x36d5>	36d1: R_X86_64_PC32	.text+0xe38c1c
36d5     36d5:	e9 00 00 00 00       	jmp    36da <.altinstr_replacement+0x36da>	36d6: R_X86_64_PC32	.text+0xe39560
36da     36da:	49 bf 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r15
36e4     36e4:	0f 01 cb             	stac
36e7     36e7:	e8 00 00 00 00       	call   36ec <.altinstr_replacement+0x36ec>	36e8: R_X86_64_PLT32	clear_user_erms-0x4
36ec     36ec:	e8 00 00 00 00       	call   36f1 <.altinstr_replacement+0x36f1>	36ed: R_X86_64_PLT32	clear_user_rep_good-0x4
36f1     36f1:	e8 00 00 00 00       	call   36f6 <.altinstr_replacement+0x36f6>	36f2: R_X86_64_PLT32	clear_user_original-0x4
36f6     36f6:	0f 01 ca             	clac
36f9     36f9:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
3703     3703:	0f 01 cb             	stac
3706     3706:	e8 00 00 00 00       	call   370b <.altinstr_replacement+0x370b>	3707: R_X86_64_PLT32	clear_user_erms-0x4
370b     370b:	e8 00 00 00 00       	call   3710 <.altinstr_replacement+0x3710>	370c: R_X86_64_PLT32	clear_user_rep_good-0x4
3710     3710:	e8 00 00 00 00       	call   3715 <.altinstr_replacement+0x3715>	3711: R_X86_64_PLT32	clear_user_original-0x4
3715     3715:	0f 01 ca             	clac
3718     3718:	e9 00 00 00 00       	jmp    371d <.altinstr_replacement+0x371d>	3719: R_X86_64_PC32	.text+0xe39fe7
371d     371d:	e9 00 00 00 00       	jmp    3722 <.altinstr_replacement+0x3722>	371e: R_X86_64_PC32	.init.text+0x100252
3722     3722:	e9 00 00 00 00       	jmp    3727 <.altinstr_replacement+0x3727>	3723: R_X86_64_PC32	.init.text+0x100308
3727     3727:	f3 48 0f b8 c7       	popcnt %rdi,%rax
372c     372c:	0f 0d 4d 00          	prefetchw 0x0(%rbp)
3730     3730:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
373a     373a:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
3744     3744:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
374e     374e:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
3758     3758:	f3 0f b8 c7          	popcnt %edi,%eax
375c     375c:	9c                   	pushf
375d     375d:	58                   	pop    %rax
375e     375e:	fa                   	cli
375f     375f:	9c                   	pushf
3760     3760:	58                   	pop    %rax
3761     3761:	fb                   	sti
3762     3762:	9c                   	pushf
3763     3763:	58                   	pop    %rax
3764     3764:	fa                   	cli
3765     3765:	9c                   	pushf
3766     3766:	58                   	pop    %rax
3767     3767:	fb                   	sti
3768     3768:	9c                   	pushf
3769     3769:	58                   	pop    %rax
376a     376a:	fa                   	cli
376b     376b:	9c                   	pushf
376c     376c:	58                   	pop    %rax
376d     376d:	fb                   	sti
376e     376e:	9c                   	pushf
376f     376f:	58                   	pop    %rax
3770     3770:	fa                   	cli
3771     3771:	9c                   	pushf
3772     3772:	58                   	pop    %rax
3773     3773:	fb                   	sti
3774     3774:	f3 0f b8 c7          	popcnt %edi,%eax
3778     3778:	f3 0f b8 c7          	popcnt %edi,%eax
377c     377c:	f3 0f b8 c7          	popcnt %edi,%eax
3780     3780:	f3 48 0f b8 c7       	popcnt %rdi,%rax
3785     3785:	f3 48 0f b8 c7       	popcnt %rdi,%rax
378a     378a:	e8 00 00 00 00       	call   378f <.altinstr_replacement+0x378f>	378b: R_X86_64_PLT32	clear_page_rep-0x4
378f     378f:	e8 00 00 00 00       	call   3794 <.altinstr_replacement+0x3794>	3790: R_X86_64_PLT32	clear_page_erms-0x4
3794     3794:	e8 00 00 00 00       	call   3799 <.altinstr_replacement+0x3799>	3795: R_X86_64_PLT32	clear_page_rep-0x4
3799     3799:	e8 00 00 00 00       	call   379e <.altinstr_replacement+0x379e>	379a: R_X86_64_PLT32	clear_page_erms-0x4
379e     379e:	9c                   	pushf
379f     379f:	58                   	pop    %rax
37a0     37a0:	fa                   	cli
37a1     37a1:	9c                   	pushf
37a2     37a2:	58                   	pop    %rax
37a3     37a3:	fb                   	sti
37a4     37a4:	e8 00 00 00 00       	call   37a9 <.altinstr_replacement+0x37a9>	37a5: R_X86_64_PLT32	clear_page_rep-0x4
37a9     37a9:	e8 00 00 00 00       	call   37ae <.altinstr_replacement+0x37ae>	37aa: R_X86_64_PLT32	clear_page_erms-0x4
37ae     37ae:	e8 00 00 00 00       	call   37b3 <.altinstr_replacement+0x37b3>	37af: R_X86_64_PLT32	clear_page_rep-0x4
37b3     37b3:	e8 00 00 00 00       	call   37b8 <.altinstr_replacement+0x37b8>	37b4: R_X86_64_PLT32	clear_page_erms-0x4
37b8     37b8:	f3 0f b8 c7          	popcnt %edi,%eax
37bc     37bc:	f3 48 0f b8 c7       	popcnt %rdi,%rax
37c1     37c1:	f3 0f b8 c7          	popcnt %edi,%eax
37c5     37c5:	f3 0f b8 c7          	popcnt %edi,%eax
37c9     37c9:	f3 0f b8 c7          	popcnt %edi,%eax
37cd     37cd:	f3 48 0f b8 c7       	popcnt %rdi,%rax
37d2     37d2:	9c                   	pushf
37d3     37d3:	58                   	pop    %rax
37d4     37d4:	fa                   	cli
37d5     37d5:	9c                   	pushf
37d6     37d6:	58                   	pop    %rax
37d7     37d7:	fb                   	sti
37d8     37d8:	9c                   	pushf
37d9     37d9:	58                   	pop    %rax
37da     37da:	fa                   	cli
37db     37db:	9c                   	pushf
37dc     37dc:	58                   	pop    %rax
37dd     37dd:	fb                   	sti
37de     37de:	9c                   	pushf
37df     37df:	58                   	pop    %rax
37e0     37e0:	fa                   	cli
37e1     37e1:	9c                   	pushf
37e2     37e2:	58                   	pop    %rax
37e3     37e3:	fb                   	sti
37e4     37e4:	f3 0f b8 c7          	popcnt %edi,%eax
37e8     37e8:	f3 0f b8 c7          	popcnt %edi,%eax
37ec     37ec:	f3 0f b8 c7          	popcnt %edi,%eax
37f0     37f0:	f3 48 0f b8 c7       	popcnt %rdi,%rax
37f5     37f5:	f3 48 0f b8 c7       	popcnt %rdi,%rax
37fa     37fa:	f3 48 0f b8 c7       	popcnt %rdi,%rax
37ff     37ff:	f3 48 0f b8 c7       	popcnt %rdi,%rax
3804     3804:	f3 48 0f b8 c7       	popcnt %rdi,%rax
3809     3809:	f3 0f b8 c7          	popcnt %edi,%eax
380d     380d:	f3 48 0f b8 c7       	popcnt %rdi,%rax
3812     3812:	e8 00 00 00 00       	call   3817 <.altinstr_replacement+0x3817>	3813: R_X86_64_PLT32	clear_page_rep-0x4
3817     3817:	e8 00 00 00 00       	call   381c <.altinstr_replacement+0x381c>	3818: R_X86_64_PLT32	clear_page_erms-0x4
381c     381c:	9c                   	pushf
381d     381d:	58                   	pop    %rax
381e     381e:	fa                   	cli
381f     381f:	9c                   	pushf
3820     3820:	58                   	pop    %rax
3821     3821:	fb                   	sti
3822     3822:	e8 00 00 00 00       	call   3827 <.altinstr_replacement+0x3827>	3823: R_X86_64_PLT32	clear_page_rep-0x4
3827     3827:	e8 00 00 00 00       	call   382c <.altinstr_replacement+0x382c>	3828: R_X86_64_PLT32	clear_page_erms-0x4
382c     382c:	f3 48 0f b8 c7       	popcnt %rdi,%rax
3831     3831:	f3 48 0f b8 c7       	popcnt %rdi,%rax
3836     3836:	9c                   	pushf
3837     3837:	58                   	pop    %rax
3838     3838:	fa                   	cli
3839     3839:	9c                   	pushf
383a     383a:	58                   	pop    %rax
383b     383b:	fb                   	sti
383c     383c:	e8 00 00 00 00       	call   3841 <.altinstr_replacement+0x3841>	383d: R_X86_64_PLT32	clear_page_rep-0x4
3841     3841:	e8 00 00 00 00       	call   3846 <.altinstr_replacement+0x3846>	3842: R_X86_64_PLT32	clear_page_erms-0x4
3846     3846:	e8 00 00 00 00       	call   384b <.altinstr_replacement+0x384b>	3847: R_X86_64_PLT32	clear_page_rep-0x4
384b     384b:	e8 00 00 00 00       	call   3850 <.altinstr_replacement+0x3850>	384c: R_X86_64_PLT32	clear_page_erms-0x4
3850     3850:	e8 00 00 00 00       	call   3855 <.altinstr_replacement+0x3855>	3851: R_X86_64_PLT32	clear_page_rep-0x4
3855     3855:	e8 00 00 00 00       	call   385a <.altinstr_replacement+0x385a>	3856: R_X86_64_PLT32	clear_page_erms-0x4
385a     385a:	0f 0d 4d 00          	prefetchw 0x0(%rbp)
385e     385e:	9c                   	pushf
385f     385f:	58                   	pop    %rax
3860     3860:	fa                   	cli
3861     3861:	9c                   	pushf
3862     3862:	58                   	pop    %rax
3863     3863:	fb                   	sti
3864     3864:	9c                   	pushf
3865     3865:	58                   	pop    %rax
3866     3866:	fa                   	cli
3867     3867:	9c                   	pushf
3868     3868:	58                   	pop    %rax
3869     3869:	fb                   	sti
386a     386a:	9c                   	pushf
386b     386b:	58                   	pop    %rax
386c     386c:	fa                   	cli
386d     386d:	9c                   	pushf
386e     386e:	58                   	pop    %rax
386f     386f:	fb                   	sti
3870     3870:	49 be 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r14
387a     387a:	e9 00 00 00 00       	jmp    387f <.altinstr_replacement+0x387f>	387b: R_X86_64_PC32	.text+0x21bae38
387f     387f:	e9 00 00 00 00       	jmp    3884 <.altinstr_replacement+0x3884>	3880: R_X86_64_PC32	.text+0x21baf6d
3884     3884:	e9 00 00 00 00       	jmp    3889 <.altinstr_replacement+0x3889>	3885: R_X86_64_PC32	.text+0x21bb1d6
3889     3889:	e9 00 00 00 00       	jmp    388e <.altinstr_replacement+0x388e>	388a: R_X86_64_PC32	.text+0x21bb2d1
388e     388e:	9c                   	pushf
388f     388f:	58                   	pop    %rax
3890     3890:	9c                   	pushf
3891     3891:	58                   	pop    %rax
3892     3892:	49 be 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r14
389c     389c:	0f 01 cb             	stac
389f     389f:	e8 00 00 00 00       	call   38a4 <.altinstr_replacement+0x38a4>	38a0: R_X86_64_PLT32	clear_user_erms-0x4
38a4     38a4:	e8 00 00 00 00       	call   38a9 <.altinstr_replacement+0x38a9>	38a5: R_X86_64_PLT32	clear_user_rep_good-0x4
38a9     38a9:	e8 00 00 00 00       	call   38ae <.altinstr_replacement+0x38ae>	38aa: R_X86_64_PLT32	clear_user_original-0x4
38ae     38ae:	0f 01 ca             	clac
38b1     38b1:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
38bb     38bb:	0f 01 cb             	stac
38be     38be:	e8 00 00 00 00       	call   38c3 <.altinstr_replacement+0x38c3>	38bf: R_X86_64_PLT32	clear_user_erms-0x4
38c3     38c3:	e8 00 00 00 00       	call   38c8 <.altinstr_replacement+0x38c8>	38c4: R_X86_64_PLT32	clear_user_rep_good-0x4
38c8     38c8:	e8 00 00 00 00       	call   38cd <.altinstr_replacement+0x38cd>	38c9: R_X86_64_PLT32	clear_user_original-0x4
38cd     38cd:	0f 01 ca             	clac
38d0     38d0:	9c                   	pushf
38d1     38d1:	58                   	pop    %rax
38d2     38d2:	fa                   	cli
38d3     38d3:	9c                   	pushf
38d4     38d4:	58                   	pop    %rax
38d5     38d5:	fb                   	sti
38d6     38d6:	f3 0f b8 c7          	popcnt %edi,%eax
38da     38da:	9c                   	pushf
38db     38db:	58                   	pop    %rax
38dc     38dc:	fa                   	cli
38dd     38dd:	9c                   	pushf
38de     38de:	58                   	pop    %rax
38df     38df:	fb                   	sti
38e0     38e0:	9c                   	pushf
38e1     38e1:	58                   	pop    %rax
38e2     38e2:	fa                   	cli
38e3     38e3:	9c                   	pushf
38e4     38e4:	58                   	pop    %rax
38e5     38e5:	fb                   	sti
38e6     38e6:	9c                   	pushf
38e7     38e7:	58                   	pop    %rax
38e8     38e8:	9c                   	pushf
38e9     38e9:	58                   	pop    %rax
38ea     38ea:	9c                   	pushf
38eb     38eb:	58                   	pop    %rax
38ec     38ec:	fa                   	cli
38ed     38ed:	9c                   	pushf
38ee     38ee:	58                   	pop    %rax
38ef     38ef:	fb                   	sti
38f0     38f0:	9c                   	pushf
38f1     38f1:	58                   	pop    %rax
38f2     38f2:	fa                   	cli
38f3     38f3:	9c                   	pushf
38f4     38f4:	58                   	pop    %rax
38f5     38f5:	fb                   	sti
38f6     38f6:	f3 0f b8 c7          	popcnt %edi,%eax
38fa     38fa:	f3 0f b8 c7          	popcnt %edi,%eax
38fe     38fe:	f3 0f b8 c7          	popcnt %edi,%eax
3902     3902:	f3 0f b8 c7          	popcnt %edi,%eax
3906     3906:	f3 0f b8 c7          	popcnt %edi,%eax
390a     390a:	f3 0f b8 c7          	popcnt %edi,%eax
390e     390e:	f3 0f b8 c7          	popcnt %edi,%eax
3912     3912:	49 be 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r14
391c     391c:	f3 0f b8 c7          	popcnt %edi,%eax
3920     3920:	f3 0f b8 c7          	popcnt %edi,%eax
3924     3924:	49 bf 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r15
392e     392e:	48 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbp
3938     3938:	f3 48 0f b8 c7       	popcnt %rdi,%rax
393d     393d:	f3 48 0f b8 c7       	popcnt %rdi,%rax
3942     3942:	48 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbp
394c     394c:	e8 00 00 00 00       	call   3951 <.altinstr_replacement+0x3951>	394d: R_X86_64_PLT32	copy_user_generic_string-0x4
3951     3951:	e8 00 00 00 00       	call   3956 <.altinstr_replacement+0x3956>	3952: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
3956     3956:	48 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbp
3960     3960:	48 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbp
396a     396a:	e8 00 00 00 00       	call   396f <.altinstr_replacement+0x396f>	396b: R_X86_64_PLT32	copy_user_generic_string-0x4
396f     396f:	e8 00 00 00 00       	call   3974 <.altinstr_replacement+0x3974>	3970: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
3974     3974:	49 be 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r14
397e     397e:	49 bf 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r15
3988     3988:	0f 01 cb             	stac
398b     398b:	e8 00 00 00 00       	call   3990 <.altinstr_replacement+0x3990>	398c: R_X86_64_PLT32	clear_user_erms-0x4
3990     3990:	e8 00 00 00 00       	call   3995 <.altinstr_replacement+0x3995>	3991: R_X86_64_PLT32	clear_user_rep_good-0x4
3995     3995:	e8 00 00 00 00       	call   399a <.altinstr_replacement+0x399a>	3996: R_X86_64_PLT32	clear_user_original-0x4
399a     399a:	0f 01 ca             	clac
399d     399d:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
39a7     39a7:	0f 01 cb             	stac
39aa     39aa:	e8 00 00 00 00       	call   39af <.altinstr_replacement+0x39af>	39ab: R_X86_64_PLT32	clear_user_erms-0x4
39af     39af:	e8 00 00 00 00       	call   39b4 <.altinstr_replacement+0x39b4>	39b0: R_X86_64_PLT32	clear_user_rep_good-0x4
39b4     39b4:	e8 00 00 00 00       	call   39b9 <.altinstr_replacement+0x39b9>	39b5: R_X86_64_PLT32	clear_user_original-0x4
39b9     39b9:	0f 01 ca             	clac
39bc     39bc:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
39c6     39c6:	0f 01 cb             	stac
39c9     39c9:	0f ae e8             	lfence
39cc     39cc:	0f 01 ca             	clac
39cf     39cf:	49 bf 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r15
39d9     39d9:	f3 0f b8 c7          	popcnt %edi,%eax
39dd     39dd:	f3 0f b8 c7          	popcnt %edi,%eax
39e1     39e1:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
39eb     39eb:	0f 01 cb             	stac
39ee     39ee:	0f ae e8             	lfence
39f1     39f1:	0f 01 ca             	clac
39f4     39f4:	0f 01 ca             	clac
39f7     39f7:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
3a01     3a01:	e8 00 00 00 00       	call   3a06 <.altinstr_replacement+0x3a06>	3a02: R_X86_64_PLT32	copy_user_generic_string-0x4
3a06     3a06:	e8 00 00 00 00       	call   3a0b <.altinstr_replacement+0x3a0b>	3a07: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
3a0b     3a0b:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
3a15     3a15:	e8 00 00 00 00       	call   3a1a <.altinstr_replacement+0x3a1a>	3a16: R_X86_64_PLT32	copy_user_generic_string-0x4
3a1a     3a1a:	e8 00 00 00 00       	call   3a1f <.altinstr_replacement+0x3a1f>	3a1b: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
3a1f     3a1f:	f3 0f b8 c7          	popcnt %edi,%eax
3a23     3a23:	f3 0f b8 c7          	popcnt %edi,%eax
3a27     3a27:	e8 00 00 00 00       	call   3a2c <.altinstr_replacement+0x3a2c>	3a28: R_X86_64_PLT32	clear_page_rep-0x4
3a2c     3a2c:	e8 00 00 00 00       	call   3a31 <.altinstr_replacement+0x3a31>	3a2d: R_X86_64_PLT32	clear_page_erms-0x4
3a31     3a31:	9c                   	pushf
3a32     3a32:	58                   	pop    %rax
3a33     3a33:	9c                   	pushf
3a34     3a34:	58                   	pop    %rax
3a35     3a35:	9c                   	pushf
3a36     3a36:	58                   	pop    %rax
3a37     3a37:	9c                   	pushf
3a38     3a38:	58                   	pop    %rax
3a39     3a39:	9c                   	pushf
3a3a     3a3a:	58                   	pop    %rax
3a3b     3a3b:	9c                   	pushf
3a3c     3a3c:	58                   	pop    %rax
3a3d     3a3d:	9c                   	pushf
3a3e     3a3e:	58                   	pop    %rax
3a3f     3a3f:	9c                   	pushf
3a40     3a40:	58                   	pop    %rax
3a41     3a41:	9c                   	pushf
3a42     3a42:	58                   	pop    %rax
3a43     3a43:	fa                   	cli
3a44     3a44:	fb                   	sti
3a45     3a45:	9c                   	pushf
3a46     3a46:	58                   	pop    %rax
3a47     3a47:	fa                   	cli
3a48     3a48:	fb                   	sti
3a49     3a49:	9c                   	pushf
3a4a     3a4a:	58                   	pop    %rax
3a4b     3a4b:	fa                   	cli
3a4c     3a4c:	fb                   	sti
3a4d     3a4d:	9c                   	pushf
3a4e     3a4e:	58                   	pop    %rax
3a4f     3a4f:	fa                   	cli
3a50     3a50:	fb                   	sti
3a51     3a51:	9c                   	pushf
3a52     3a52:	58                   	pop    %rax
3a53     3a53:	fa                   	cli
3a54     3a54:	fb                   	sti
3a55     3a55:	9c                   	pushf
3a56     3a56:	58                   	pop    %rax
3a57     3a57:	fa                   	cli
3a58     3a58:	fb                   	sti
3a59     3a59:	9c                   	pushf
3a5a     3a5a:	58                   	pop    %rax
3a5b     3a5b:	fa                   	cli
3a5c     3a5c:	fb                   	sti
3a5d     3a5d:	9c                   	pushf
3a5e     3a5e:	58                   	pop    %rax
3a5f     3a5f:	fa                   	cli
3a60     3a60:	fb                   	sti
3a61     3a61:	9c                   	pushf
3a62     3a62:	58                   	pop    %rax
3a63     3a63:	fa                   	cli
3a64     3a64:	fb                   	sti
3a65     3a65:	9c                   	pushf
3a66     3a66:	58                   	pop    %rax
3a67     3a67:	fa                   	cli
3a68     3a68:	fb                   	sti
3a69     3a69:	9c                   	pushf
3a6a     3a6a:	58                   	pop    %rax
3a6b     3a6b:	fa                   	cli
3a6c     3a6c:	fb                   	sti
3a6d     3a6d:	9c                   	pushf
3a6e     3a6e:	58                   	pop    %rax
3a6f     3a6f:	fa                   	cli
3a70     3a70:	fb                   	sti
3a71     3a71:	9c                   	pushf
3a72     3a72:	58                   	pop    %rax
3a73     3a73:	fa                   	cli
3a74     3a74:	fb                   	sti
3a75     3a75:	9c                   	pushf
3a76     3a76:	58                   	pop    %rax
3a77     3a77:	fa                   	cli
3a78     3a78:	fb                   	sti
3a79     3a79:	9c                   	pushf
3a7a     3a7a:	58                   	pop    %rax
3a7b     3a7b:	fa                   	cli
3a7c     3a7c:	fb                   	sti
3a7d     3a7d:	9c                   	pushf
3a7e     3a7e:	58                   	pop    %rax
3a7f     3a7f:	fa                   	cli
3a80     3a80:	fb                   	sti
3a81     3a81:	9c                   	pushf
3a82     3a82:	58                   	pop    %rax
3a83     3a83:	fa                   	cli
3a84     3a84:	fb                   	sti
3a85     3a85:	9c                   	pushf
3a86     3a86:	58                   	pop    %rax
3a87     3a87:	fa                   	cli
3a88     3a88:	fb                   	sti
3a89     3a89:	9c                   	pushf
3a8a     3a8a:	58                   	pop    %rax
3a8b     3a8b:	fa                   	cli
3a8c     3a8c:	fb                   	sti
3a8d     3a8d:	9c                   	pushf
3a8e     3a8e:	58                   	pop    %rax
3a8f     3a8f:	fa                   	cli
3a90     3a90:	fb                   	sti
3a91     3a91:	9c                   	pushf
3a92     3a92:	58                   	pop    %rax
3a93     3a93:	fa                   	cli
3a94     3a94:	fb                   	sti
3a95     3a95:	9c                   	pushf
3a96     3a96:	58                   	pop    %rax
3a97     3a97:	fa                   	cli
3a98     3a98:	fb                   	sti
3a99     3a99:	9c                   	pushf
3a9a     3a9a:	58                   	pop    %rax
3a9b     3a9b:	fa                   	cli
3a9c     3a9c:	fb                   	sti
3a9d     3a9d:	9c                   	pushf
3a9e     3a9e:	58                   	pop    %rax
3a9f     3a9f:	fa                   	cli
3aa0     3aa0:	fb                   	sti
3aa1     3aa1:	9c                   	pushf
3aa2     3aa2:	58                   	pop    %rax
3aa3     3aa3:	fa                   	cli
3aa4     3aa4:	fb                   	sti
3aa5     3aa5:	9c                   	pushf
3aa6     3aa6:	58                   	pop    %rax
3aa7     3aa7:	fa                   	cli
3aa8     3aa8:	fb                   	sti
3aa9     3aa9:	9c                   	pushf
3aaa     3aaa:	58                   	pop    %rax
3aab     3aab:	fa                   	cli
3aac     3aac:	fb                   	sti
3aad     3aad:	9c                   	pushf
3aae     3aae:	58                   	pop    %rax
3aaf     3aaf:	fa                   	cli
3ab0     3ab0:	fb                   	sti
3ab1     3ab1:	9c                   	pushf
3ab2     3ab2:	58                   	pop    %rax
3ab3     3ab3:	fa                   	cli
3ab4     3ab4:	fb                   	sti
3ab5     3ab5:	9c                   	pushf
3ab6     3ab6:	58                   	pop    %rax
3ab7     3ab7:	fa                   	cli
3ab8     3ab8:	fb                   	sti
3ab9     3ab9:	9c                   	pushf
3aba     3aba:	58                   	pop    %rax
3abb     3abb:	fa                   	cli
3abc     3abc:	fb                   	sti
3abd     3abd:	9c                   	pushf
3abe     3abe:	58                   	pop    %rax
3abf     3abf:	fa                   	cli
3ac0     3ac0:	fb                   	sti
3ac1     3ac1:	9c                   	pushf
3ac2     3ac2:	58                   	pop    %rax
3ac3     3ac3:	fa                   	cli
3ac4     3ac4:	fb                   	sti
3ac5     3ac5:	9c                   	pushf
3ac6     3ac6:	58                   	pop    %rax
3ac7     3ac7:	fa                   	cli
3ac8     3ac8:	fb                   	sti
3ac9     3ac9:	9c                   	pushf
3aca     3aca:	58                   	pop    %rax
3acb     3acb:	fa                   	cli
3acc     3acc:	fb                   	sti
3acd     3acd:	9c                   	pushf
3ace     3ace:	58                   	pop    %rax
3acf     3acf:	fa                   	cli
3ad0     3ad0:	fb                   	sti
3ad1     3ad1:	9c                   	pushf
3ad2     3ad2:	58                   	pop    %rax
3ad3     3ad3:	fa                   	cli
3ad4     3ad4:	fb                   	sti
3ad5     3ad5:	9c                   	pushf
3ad6     3ad6:	58                   	pop    %rax
3ad7     3ad7:	fa                   	cli
3ad8     3ad8:	fb                   	sti
3ad9     3ad9:	9c                   	pushf
3ada     3ada:	58                   	pop    %rax
3adb     3adb:	fa                   	cli
3adc     3adc:	fb                   	sti
3add     3add:	9c                   	pushf
3ade     3ade:	58                   	pop    %rax
3adf     3adf:	fa                   	cli
3ae0     3ae0:	fb                   	sti
3ae1     3ae1:	9c                   	pushf
3ae2     3ae2:	58                   	pop    %rax
3ae3     3ae3:	fa                   	cli
3ae4     3ae4:	fb                   	sti
3ae5     3ae5:	9c                   	pushf
3ae6     3ae6:	58                   	pop    %rax
3ae7     3ae7:	fa                   	cli
3ae8     3ae8:	fb                   	sti
3ae9     3ae9:	9c                   	pushf
3aea     3aea:	58                   	pop    %rax
3aeb     3aeb:	fa                   	cli
3aec     3aec:	fb                   	sti
3aed     3aed:	9c                   	pushf
3aee     3aee:	58                   	pop    %rax
3aef     3aef:	fa                   	cli
3af0     3af0:	fb                   	sti
3af1     3af1:	9c                   	pushf
3af2     3af2:	58                   	pop    %rax
3af3     3af3:	fa                   	cli
3af4     3af4:	fb                   	sti
3af5     3af5:	9c                   	pushf
3af6     3af6:	58                   	pop    %rax
3af7     3af7:	fa                   	cli
3af8     3af8:	fb                   	sti
3af9     3af9:	9c                   	pushf
3afa     3afa:	58                   	pop    %rax
3afb     3afb:	fa                   	cli
3afc     3afc:	fb                   	sti
3afd     3afd:	9c                   	pushf
3afe     3afe:	58                   	pop    %rax
3aff     3aff:	fa                   	cli
3b00     3b00:	fb                   	sti
3b01     3b01:	9c                   	pushf
3b02     3b02:	58                   	pop    %rax
3b03     3b03:	fa                   	cli
3b04     3b04:	fb                   	sti
3b05     3b05:	9c                   	pushf
3b06     3b06:	58                   	pop    %rax
3b07     3b07:	fa                   	cli
3b08     3b08:	fb                   	sti
3b09     3b09:	9c                   	pushf
3b0a     3b0a:	58                   	pop    %rax
3b0b     3b0b:	fa                   	cli
3b0c     3b0c:	fb                   	sti
3b0d     3b0d:	9c                   	pushf
3b0e     3b0e:	58                   	pop    %rax
3b0f     3b0f:	fa                   	cli
3b10     3b10:	fb                   	sti
3b11     3b11:	9c                   	pushf
3b12     3b12:	58                   	pop    %rax
3b13     3b13:	fa                   	cli
3b14     3b14:	fb                   	sti
3b15     3b15:	9c                   	pushf
3b16     3b16:	58                   	pop    %rax
3b17     3b17:	fa                   	cli
3b18     3b18:	fb                   	sti
3b19     3b19:	9c                   	pushf
3b1a     3b1a:	58                   	pop    %rax
3b1b     3b1b:	fa                   	cli
3b1c     3b1c:	fb                   	sti
3b1d     3b1d:	9c                   	pushf
3b1e     3b1e:	58                   	pop    %rax
3b1f     3b1f:	fa                   	cli
3b20     3b20:	fb                   	sti
3b21     3b21:	9c                   	pushf
3b22     3b22:	58                   	pop    %rax
3b23     3b23:	fa                   	cli
3b24     3b24:	fb                   	sti
3b25     3b25:	9c                   	pushf
3b26     3b26:	58                   	pop    %rax
3b27     3b27:	fa                   	cli
3b28     3b28:	fb                   	sti
3b29     3b29:	9c                   	pushf
3b2a     3b2a:	58                   	pop    %rax
3b2b     3b2b:	fa                   	cli
3b2c     3b2c:	fb                   	sti
3b2d     3b2d:	9c                   	pushf
3b2e     3b2e:	58                   	pop    %rax
3b2f     3b2f:	fa                   	cli
3b30     3b30:	fb                   	sti
3b31     3b31:	9c                   	pushf
3b32     3b32:	58                   	pop    %rax
3b33     3b33:	fa                   	cli
3b34     3b34:	fb                   	sti
3b35     3b35:	9c                   	pushf
3b36     3b36:	58                   	pop    %rax
3b37     3b37:	fa                   	cli
3b38     3b38:	fb                   	sti
3b39     3b39:	9c                   	pushf
3b3a     3b3a:	58                   	pop    %rax
3b3b     3b3b:	fa                   	cli
3b3c     3b3c:	fb                   	sti
3b3d     3b3d:	9c                   	pushf
3b3e     3b3e:	58                   	pop    %rax
3b3f     3b3f:	fa                   	cli
3b40     3b40:	fb                   	sti
3b41     3b41:	9c                   	pushf
3b42     3b42:	58                   	pop    %rax
3b43     3b43:	fa                   	cli
3b44     3b44:	fb                   	sti
3b45     3b45:	9c                   	pushf
3b46     3b46:	58                   	pop    %rax
3b47     3b47:	fa                   	cli
3b48     3b48:	fb                   	sti
3b49     3b49:	9c                   	pushf
3b4a     3b4a:	58                   	pop    %rax
3b4b     3b4b:	fa                   	cli
3b4c     3b4c:	fb                   	sti
3b4d     3b4d:	9c                   	pushf
3b4e     3b4e:	58                   	pop    %rax
3b4f     3b4f:	fa                   	cli
3b50     3b50:	fb                   	sti
3b51     3b51:	9c                   	pushf
3b52     3b52:	58                   	pop    %rax
3b53     3b53:	fa                   	cli
3b54     3b54:	fb                   	sti
3b55     3b55:	9c                   	pushf
3b56     3b56:	58                   	pop    %rax
3b57     3b57:	fa                   	cli
3b58     3b58:	fb                   	sti
3b59     3b59:	9c                   	pushf
3b5a     3b5a:	58                   	pop    %rax
3b5b     3b5b:	fa                   	cli
3b5c     3b5c:	fb                   	sti
3b5d     3b5d:	9c                   	pushf
3b5e     3b5e:	58                   	pop    %rax
3b5f     3b5f:	fa                   	cli
3b60     3b60:	fb                   	sti
3b61     3b61:	9c                   	pushf
3b62     3b62:	58                   	pop    %rax
3b63     3b63:	fa                   	cli
3b64     3b64:	fb                   	sti
3b65     3b65:	9c                   	pushf
3b66     3b66:	58                   	pop    %rax
3b67     3b67:	fa                   	cli
3b68     3b68:	fb                   	sti
3b69     3b69:	9c                   	pushf
3b6a     3b6a:	58                   	pop    %rax
3b6b     3b6b:	fa                   	cli
3b6c     3b6c:	fb                   	sti
3b6d     3b6d:	9c                   	pushf
3b6e     3b6e:	58                   	pop    %rax
3b6f     3b6f:	fa                   	cli
3b70     3b70:	fb                   	sti
3b71     3b71:	9c                   	pushf
3b72     3b72:	58                   	pop    %rax
3b73     3b73:	fa                   	cli
3b74     3b74:	fb                   	sti
3b75     3b75:	9c                   	pushf
3b76     3b76:	58                   	pop    %rax
3b77     3b77:	fa                   	cli
3b78     3b78:	fb                   	sti
3b79     3b79:	9c                   	pushf
3b7a     3b7a:	58                   	pop    %rax
3b7b     3b7b:	fa                   	cli
3b7c     3b7c:	fb                   	sti
3b7d     3b7d:	9c                   	pushf
3b7e     3b7e:	58                   	pop    %rax
3b7f     3b7f:	fa                   	cli
3b80     3b80:	fb                   	sti
3b81     3b81:	9c                   	pushf
3b82     3b82:	58                   	pop    %rax
3b83     3b83:	fa                   	cli
3b84     3b84:	fb                   	sti
3b85     3b85:	9c                   	pushf
3b86     3b86:	58                   	pop    %rax
3b87     3b87:	fa                   	cli
3b88     3b88:	fb                   	sti
3b89     3b89:	9c                   	pushf
3b8a     3b8a:	58                   	pop    %rax
3b8b     3b8b:	fa                   	cli
3b8c     3b8c:	fb                   	sti
3b8d     3b8d:	9c                   	pushf
3b8e     3b8e:	58                   	pop    %rax
3b8f     3b8f:	fa                   	cli
3b90     3b90:	fb                   	sti
3b91     3b91:	9c                   	pushf
3b92     3b92:	58                   	pop    %rax
3b93     3b93:	fa                   	cli
3b94     3b94:	fb                   	sti
3b95     3b95:	9c                   	pushf
3b96     3b96:	58                   	pop    %rax
3b97     3b97:	fa                   	cli
3b98     3b98:	fb                   	sti
3b99     3b99:	9c                   	pushf
3b9a     3b9a:	58                   	pop    %rax
3b9b     3b9b:	fa                   	cli
3b9c     3b9c:	fb                   	sti
3b9d     3b9d:	9c                   	pushf
3b9e     3b9e:	58                   	pop    %rax
3b9f     3b9f:	fa                   	cli
3ba0     3ba0:	fb                   	sti
3ba1     3ba1:	9c                   	pushf
3ba2     3ba2:	58                   	pop    %rax
3ba3     3ba3:	fa                   	cli
3ba4     3ba4:	fb                   	sti
3ba5     3ba5:	9c                   	pushf
3ba6     3ba6:	58                   	pop    %rax
3ba7     3ba7:	fa                   	cli
3ba8     3ba8:	fb                   	sti
3ba9     3ba9:	9c                   	pushf
3baa     3baa:	58                   	pop    %rax
3bab     3bab:	fa                   	cli
3bac     3bac:	fb                   	sti
3bad     3bad:	9c                   	pushf
3bae     3bae:	58                   	pop    %rax
3baf     3baf:	fa                   	cli
3bb0     3bb0:	fb                   	sti
3bb1     3bb1:	9c                   	pushf
3bb2     3bb2:	58                   	pop    %rax
3bb3     3bb3:	fa                   	cli
3bb4     3bb4:	fb                   	sti
3bb5     3bb5:	9c                   	pushf
3bb6     3bb6:	58                   	pop    %rax
3bb7     3bb7:	fa                   	cli
3bb8     3bb8:	fb                   	sti
3bb9     3bb9:	9c                   	pushf
3bba     3bba:	58                   	pop    %rax
3bbb     3bbb:	fa                   	cli
3bbc     3bbc:	fb                   	sti
3bbd     3bbd:	9c                   	pushf
3bbe     3bbe:	58                   	pop    %rax
3bbf     3bbf:	fa                   	cli
3bc0     3bc0:	fb                   	sti
3bc1     3bc1:	9c                   	pushf
3bc2     3bc2:	58                   	pop    %rax
3bc3     3bc3:	fa                   	cli
3bc4     3bc4:	fb                   	sti
3bc5     3bc5:	9c                   	pushf
3bc6     3bc6:	58                   	pop    %rax
3bc7     3bc7:	fa                   	cli
3bc8     3bc8:	fb                   	sti
3bc9     3bc9:	9c                   	pushf
3bca     3bca:	58                   	pop    %rax
3bcb     3bcb:	fa                   	cli
3bcc     3bcc:	fb                   	sti
3bcd     3bcd:	9c                   	pushf
3bce     3bce:	58                   	pop    %rax
3bcf     3bcf:	fa                   	cli
3bd0     3bd0:	fb                   	sti
3bd1     3bd1:	9c                   	pushf
3bd2     3bd2:	58                   	pop    %rax
3bd3     3bd3:	fa                   	cli
3bd4     3bd4:	fb                   	sti
3bd5     3bd5:	9c                   	pushf
3bd6     3bd6:	58                   	pop    %rax
3bd7     3bd7:	fa                   	cli
3bd8     3bd8:	fb                   	sti
3bd9     3bd9:	9c                   	pushf
3bda     3bda:	58                   	pop    %rax
3bdb     3bdb:	fa                   	cli
3bdc     3bdc:	fb                   	sti
3bdd     3bdd:	9c                   	pushf
3bde     3bde:	58                   	pop    %rax
3bdf     3bdf:	fa                   	cli
3be0     3be0:	fb                   	sti
3be1     3be1:	9c                   	pushf
3be2     3be2:	58                   	pop    %rax
3be3     3be3:	fa                   	cli
3be4     3be4:	fb                   	sti
3be5     3be5:	9c                   	pushf
3be6     3be6:	58                   	pop    %rax
3be7     3be7:	fa                   	cli
3be8     3be8:	fb                   	sti
3be9     3be9:	9c                   	pushf
3bea     3bea:	58                   	pop    %rax
3beb     3beb:	fa                   	cli
3bec     3bec:	fb                   	sti
3bed     3bed:	9c                   	pushf
3bee     3bee:	58                   	pop    %rax
3bef     3bef:	fa                   	cli
3bf0     3bf0:	fb                   	sti
3bf1     3bf1:	9c                   	pushf
3bf2     3bf2:	58                   	pop    %rax
3bf3     3bf3:	fa                   	cli
3bf4     3bf4:	fb                   	sti
3bf5     3bf5:	9c                   	pushf
3bf6     3bf6:	58                   	pop    %rax
3bf7     3bf7:	fa                   	cli
3bf8     3bf8:	fb                   	sti
3bf9     3bf9:	9c                   	pushf
3bfa     3bfa:	58                   	pop    %rax
3bfb     3bfb:	fa                   	cli
3bfc     3bfc:	fb                   	sti
3bfd     3bfd:	9c                   	pushf
3bfe     3bfe:	58                   	pop    %rax
3bff     3bff:	fa                   	cli
3c00     3c00:	fb                   	sti
3c01     3c01:	9c                   	pushf
3c02     3c02:	58                   	pop    %rax
3c03     3c03:	fa                   	cli
3c04     3c04:	fb                   	sti
3c05     3c05:	9c                   	pushf
3c06     3c06:	58                   	pop    %rax
3c07     3c07:	fa                   	cli
3c08     3c08:	fb                   	sti
3c09     3c09:	9c                   	pushf
3c0a     3c0a:	58                   	pop    %rax
3c0b     3c0b:	fa                   	cli
3c0c     3c0c:	fb                   	sti
3c0d     3c0d:	9c                   	pushf
3c0e     3c0e:	58                   	pop    %rax
3c0f     3c0f:	fa                   	cli
3c10     3c10:	fb                   	sti
3c11     3c11:	9c                   	pushf
3c12     3c12:	58                   	pop    %rax
3c13     3c13:	fa                   	cli
3c14     3c14:	fb                   	sti
3c15     3c15:	9c                   	pushf
3c16     3c16:	58                   	pop    %rax
3c17     3c17:	fa                   	cli
3c18     3c18:	fb                   	sti
3c19     3c19:	9c                   	pushf
3c1a     3c1a:	58                   	pop    %rax
3c1b     3c1b:	fa                   	cli
3c1c     3c1c:	fb                   	sti
3c1d     3c1d:	9c                   	pushf
3c1e     3c1e:	58                   	pop    %rax
3c1f     3c1f:	fa                   	cli
3c20     3c20:	fb                   	sti
3c21     3c21:	9c                   	pushf
3c22     3c22:	58                   	pop    %rax
3c23     3c23:	fa                   	cli
3c24     3c24:	fb                   	sti
3c25     3c25:	9c                   	pushf
3c26     3c26:	58                   	pop    %rax
3c27     3c27:	fa                   	cli
3c28     3c28:	fb                   	sti
3c29     3c29:	9c                   	pushf
3c2a     3c2a:	58                   	pop    %rax
3c2b     3c2b:	fa                   	cli
3c2c     3c2c:	fb                   	sti
3c2d     3c2d:	9c                   	pushf
3c2e     3c2e:	58                   	pop    %rax
3c2f     3c2f:	fa                   	cli
3c30     3c30:	fb                   	sti
3c31     3c31:	9c                   	pushf
3c32     3c32:	58                   	pop    %rax
3c33     3c33:	fa                   	cli
3c34     3c34:	fb                   	sti
3c35     3c35:	9c                   	pushf
3c36     3c36:	58                   	pop    %rax
3c37     3c37:	fa                   	cli
3c38     3c38:	fb                   	sti
3c39     3c39:	9c                   	pushf
3c3a     3c3a:	58                   	pop    %rax
3c3b     3c3b:	fa                   	cli
3c3c     3c3c:	fb                   	sti
3c3d     3c3d:	9c                   	pushf
3c3e     3c3e:	58                   	pop    %rax
3c3f     3c3f:	fa                   	cli
3c40     3c40:	fb                   	sti
3c41     3c41:	9c                   	pushf
3c42     3c42:	58                   	pop    %rax
3c43     3c43:	fa                   	cli
3c44     3c44:	fb                   	sti
3c45     3c45:	9c                   	pushf
3c46     3c46:	58                   	pop    %rax
3c47     3c47:	fa                   	cli
3c48     3c48:	fb                   	sti
3c49     3c49:	9c                   	pushf
3c4a     3c4a:	58                   	pop    %rax
3c4b     3c4b:	fa                   	cli
3c4c     3c4c:	fb                   	sti
3c4d     3c4d:	9c                   	pushf
3c4e     3c4e:	58                   	pop    %rax
3c4f     3c4f:	fa                   	cli
3c50     3c50:	fb                   	sti
3c51     3c51:	9c                   	pushf
3c52     3c52:	58                   	pop    %rax
3c53     3c53:	fa                   	cli
3c54     3c54:	fb                   	sti
3c55     3c55:	9c                   	pushf
3c56     3c56:	58                   	pop    %rax
3c57     3c57:	fa                   	cli
3c58     3c58:	fb                   	sti
3c59     3c59:	9c                   	pushf
3c5a     3c5a:	58                   	pop    %rax
3c5b     3c5b:	fa                   	cli
3c5c     3c5c:	fb                   	sti
3c5d     3c5d:	9c                   	pushf
3c5e     3c5e:	58                   	pop    %rax
3c5f     3c5f:	fa                   	cli
3c60     3c60:	fb                   	sti
3c61     3c61:	9c                   	pushf
3c62     3c62:	58                   	pop    %rax
3c63     3c63:	fa                   	cli
3c64     3c64:	fb                   	sti
3c65     3c65:	9c                   	pushf
3c66     3c66:	58                   	pop    %rax
3c67     3c67:	fa                   	cli
3c68     3c68:	fb                   	sti
3c69     3c69:	9c                   	pushf
3c6a     3c6a:	58                   	pop    %rax
3c6b     3c6b:	fa                   	cli
3c6c     3c6c:	fb                   	sti
3c6d     3c6d:	9c                   	pushf
3c6e     3c6e:	58                   	pop    %rax
3c6f     3c6f:	fa                   	cli
3c70     3c70:	fb                   	sti
3c71     3c71:	9c                   	pushf
3c72     3c72:	58                   	pop    %rax
3c73     3c73:	fa                   	cli
3c74     3c74:	fb                   	sti
3c75     3c75:	9c                   	pushf
3c76     3c76:	58                   	pop    %rax
3c77     3c77:	fa                   	cli
3c78     3c78:	fb                   	sti
3c79     3c79:	9c                   	pushf
3c7a     3c7a:	58                   	pop    %rax
3c7b     3c7b:	fa                   	cli
3c7c     3c7c:	fb                   	sti
3c7d     3c7d:	9c                   	pushf
3c7e     3c7e:	58                   	pop    %rax
3c7f     3c7f:	fa                   	cli
3c80     3c80:	fb                   	sti
3c81     3c81:	9c                   	pushf
3c82     3c82:	58                   	pop    %rax
3c83     3c83:	fa                   	cli
3c84     3c84:	fb                   	sti
3c85     3c85:	9c                   	pushf
3c86     3c86:	58                   	pop    %rax
3c87     3c87:	fa                   	cli
3c88     3c88:	fb                   	sti
3c89     3c89:	9c                   	pushf
3c8a     3c8a:	58                   	pop    %rax
3c8b     3c8b:	fa                   	cli
3c8c     3c8c:	fb                   	sti
3c8d     3c8d:	9c                   	pushf
3c8e     3c8e:	58                   	pop    %rax
3c8f     3c8f:	fa                   	cli
3c90     3c90:	fb                   	sti
3c91     3c91:	9c                   	pushf
3c92     3c92:	58                   	pop    %rax
3c93     3c93:	fa                   	cli
3c94     3c94:	fb                   	sti
3c95     3c95:	9c                   	pushf
3c96     3c96:	58                   	pop    %rax
3c97     3c97:	fa                   	cli
3c98     3c98:	fb                   	sti
3c99     3c99:	9c                   	pushf
3c9a     3c9a:	58                   	pop    %rax
3c9b     3c9b:	fa                   	cli
3c9c     3c9c:	fb                   	sti
3c9d     3c9d:	9c                   	pushf
3c9e     3c9e:	58                   	pop    %rax
3c9f     3c9f:	fa                   	cli
3ca0     3ca0:	fb                   	sti
3ca1     3ca1:	9c                   	pushf
3ca2     3ca2:	58                   	pop    %rax
3ca3     3ca3:	fa                   	cli
3ca4     3ca4:	fb                   	sti
3ca5     3ca5:	9c                   	pushf
3ca6     3ca6:	58                   	pop    %rax
3ca7     3ca7:	fa                   	cli
3ca8     3ca8:	fb                   	sti
3ca9     3ca9:	9c                   	pushf
3caa     3caa:	58                   	pop    %rax
3cab     3cab:	fa                   	cli
3cac     3cac:	fb                   	sti
3cad     3cad:	9c                   	pushf
3cae     3cae:	58                   	pop    %rax
3caf     3caf:	fa                   	cli
3cb0     3cb0:	fb                   	sti
3cb1     3cb1:	9c                   	pushf
3cb2     3cb2:	58                   	pop    %rax
3cb3     3cb3:	fa                   	cli
3cb4     3cb4:	fb                   	sti
3cb5     3cb5:	9c                   	pushf
3cb6     3cb6:	58                   	pop    %rax
3cb7     3cb7:	fa                   	cli
3cb8     3cb8:	fb                   	sti
3cb9     3cb9:	9c                   	pushf
3cba     3cba:	58                   	pop    %rax
3cbb     3cbb:	fa                   	cli
3cbc     3cbc:	fb                   	sti
3cbd     3cbd:	9c                   	pushf
3cbe     3cbe:	58                   	pop    %rax
3cbf     3cbf:	fa                   	cli
3cc0     3cc0:	fb                   	sti
3cc1     3cc1:	9c                   	pushf
3cc2     3cc2:	58                   	pop    %rax
3cc3     3cc3:	fa                   	cli
3cc4     3cc4:	fb                   	sti
3cc5     3cc5:	9c                   	pushf
3cc6     3cc6:	58                   	pop    %rax
3cc7     3cc7:	fa                   	cli
3cc8     3cc8:	fb                   	sti
3cc9     3cc9:	9c                   	pushf
3cca     3cca:	58                   	pop    %rax
3ccb     3ccb:	fa                   	cli
3ccc     3ccc:	fb                   	sti
3ccd     3ccd:	9c                   	pushf
3cce     3cce:	58                   	pop    %rax
3ccf     3ccf:	fa                   	cli
3cd0     3cd0:	fb                   	sti
3cd1     3cd1:	9c                   	pushf
3cd2     3cd2:	58                   	pop    %rax
3cd3     3cd3:	fa                   	cli
3cd4     3cd4:	fb                   	sti
3cd5     3cd5:	9c                   	pushf
3cd6     3cd6:	58                   	pop    %rax
3cd7     3cd7:	fa                   	cli
3cd8     3cd8:	fb                   	sti
3cd9     3cd9:	9c                   	pushf
3cda     3cda:	58                   	pop    %rax
3cdb     3cdb:	fa                   	cli
3cdc     3cdc:	fb                   	sti
3cdd     3cdd:	9c                   	pushf
3cde     3cde:	58                   	pop    %rax
3cdf     3cdf:	fa                   	cli
3ce0     3ce0:	fb                   	sti
3ce1     3ce1:	9c                   	pushf
3ce2     3ce2:	58                   	pop    %rax
3ce3     3ce3:	fa                   	cli
3ce4     3ce4:	fb                   	sti
3ce5     3ce5:	9c                   	pushf
3ce6     3ce6:	58                   	pop    %rax
3ce7     3ce7:	fa                   	cli
3ce8     3ce8:	fb                   	sti
3ce9     3ce9:	9c                   	pushf
3cea     3cea:	58                   	pop    %rax
3ceb     3ceb:	fa                   	cli
3cec     3cec:	fb                   	sti
3ced     3ced:	9c                   	pushf
3cee     3cee:	58                   	pop    %rax
3cef     3cef:	fa                   	cli
3cf0     3cf0:	fb                   	sti
3cf1     3cf1:	9c                   	pushf
3cf2     3cf2:	58                   	pop    %rax
3cf3     3cf3:	fa                   	cli
3cf4     3cf4:	fb                   	sti
3cf5     3cf5:	9c                   	pushf
3cf6     3cf6:	58                   	pop    %rax
3cf7     3cf7:	fa                   	cli
3cf8     3cf8:	fb                   	sti
3cf9     3cf9:	9c                   	pushf
3cfa     3cfa:	58                   	pop    %rax
3cfb     3cfb:	fa                   	cli
3cfc     3cfc:	fb                   	sti
3cfd     3cfd:	9c                   	pushf
3cfe     3cfe:	58                   	pop    %rax
3cff     3cff:	fa                   	cli
3d00     3d00:	fb                   	sti
3d01     3d01:	9c                   	pushf
3d02     3d02:	58                   	pop    %rax
3d03     3d03:	fa                   	cli
3d04     3d04:	fb                   	sti
3d05     3d05:	9c                   	pushf
3d06     3d06:	58                   	pop    %rax
3d07     3d07:	fa                   	cli
3d08     3d08:	fb                   	sti
3d09     3d09:	9c                   	pushf
3d0a     3d0a:	58                   	pop    %rax
3d0b     3d0b:	fa                   	cli
3d0c     3d0c:	fb                   	sti
3d0d     3d0d:	9c                   	pushf
3d0e     3d0e:	58                   	pop    %rax
3d0f     3d0f:	fa                   	cli
3d10     3d10:	fb                   	sti
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
3d23     3d23:	fa                   	cli
3d24     3d24:	fb                   	sti
3d25     3d25:	9c                   	pushf
3d26     3d26:	58                   	pop    %rax
3d27     3d27:	fa                   	cli
3d28     3d28:	fb                   	sti
3d29     3d29:	9c                   	pushf
3d2a     3d2a:	58                   	pop    %rax
3d2b     3d2b:	fa                   	cli
3d2c     3d2c:	fb                   	sti
3d2d     3d2d:	9c                   	pushf
3d2e     3d2e:	58                   	pop    %rax
3d2f     3d2f:	fa                   	cli
3d30     3d30:	fb                   	sti
3d31     3d31:	9c                   	pushf
3d32     3d32:	58                   	pop    %rax
3d33     3d33:	fa                   	cli
3d34     3d34:	fb                   	sti
3d35     3d35:	9c                   	pushf
3d36     3d36:	58                   	pop    %rax
3d37     3d37:	fa                   	cli
3d38     3d38:	fb                   	sti
3d39     3d39:	9c                   	pushf
3d3a     3d3a:	58                   	pop    %rax
3d3b     3d3b:	fa                   	cli
3d3c     3d3c:	fb                   	sti
3d3d     3d3d:	9c                   	pushf
3d3e     3d3e:	58                   	pop    %rax
3d3f     3d3f:	fa                   	cli
3d40     3d40:	fb                   	sti
3d41     3d41:	9c                   	pushf
3d42     3d42:	58                   	pop    %rax
3d43     3d43:	fa                   	cli
3d44     3d44:	fb                   	sti
3d45     3d45:	9c                   	pushf
3d46     3d46:	58                   	pop    %rax
3d47     3d47:	fa                   	cli
3d48     3d48:	fb                   	sti
3d49     3d49:	9c                   	pushf
3d4a     3d4a:	58                   	pop    %rax
3d4b     3d4b:	fa                   	cli
3d4c     3d4c:	fb                   	sti
3d4d     3d4d:	9c                   	pushf
3d4e     3d4e:	58                   	pop    %rax
3d4f     3d4f:	fa                   	cli
3d50     3d50:	fb                   	sti
3d51     3d51:	9c                   	pushf
3d52     3d52:	58                   	pop    %rax
3d53     3d53:	fa                   	cli
3d54     3d54:	fb                   	sti
3d55     3d55:	9c                   	pushf
3d56     3d56:	58                   	pop    %rax
3d57     3d57:	fa                   	cli
3d58     3d58:	fb                   	sti
3d59     3d59:	9c                   	pushf
3d5a     3d5a:	58                   	pop    %rax
3d5b     3d5b:	fa                   	cli
3d5c     3d5c:	fb                   	sti
3d5d     3d5d:	9c                   	pushf
3d5e     3d5e:	58                   	pop    %rax
3d5f     3d5f:	fa                   	cli
3d60     3d60:	fb                   	sti
3d61     3d61:	9c                   	pushf
3d62     3d62:	58                   	pop    %rax
3d63     3d63:	fa                   	cli
3d64     3d64:	fb                   	sti
3d65     3d65:	9c                   	pushf
3d66     3d66:	58                   	pop    %rax
3d67     3d67:	fa                   	cli
3d68     3d68:	fb                   	sti
3d69     3d69:	9c                   	pushf
3d6a     3d6a:	58                   	pop    %rax
3d6b     3d6b:	fa                   	cli
3d6c     3d6c:	fb                   	sti
3d6d     3d6d:	9c                   	pushf
3d6e     3d6e:	58                   	pop    %rax
3d6f     3d6f:	fa                   	cli
3d70     3d70:	fb                   	sti
3d71     3d71:	9c                   	pushf
3d72     3d72:	58                   	pop    %rax
3d73     3d73:	fa                   	cli
3d74     3d74:	fb                   	sti
3d75     3d75:	9c                   	pushf
3d76     3d76:	58                   	pop    %rax
3d77     3d77:	fa                   	cli
3d78     3d78:	fb                   	sti
3d79     3d79:	9c                   	pushf
3d7a     3d7a:	58                   	pop    %rax
3d7b     3d7b:	fa                   	cli
3d7c     3d7c:	fb                   	sti
3d7d     3d7d:	9c                   	pushf
3d7e     3d7e:	58                   	pop    %rax
3d7f     3d7f:	fa                   	cli
3d80     3d80:	fb                   	sti
3d81     3d81:	9c                   	pushf
3d82     3d82:	58                   	pop    %rax
3d83     3d83:	fa                   	cli
3d84     3d84:	fb                   	sti
3d85     3d85:	9c                   	pushf
3d86     3d86:	58                   	pop    %rax
3d87     3d87:	fa                   	cli
3d88     3d88:	fb                   	sti
3d89     3d89:	9c                   	pushf
3d8a     3d8a:	58                   	pop    %rax
3d8b     3d8b:	fa                   	cli
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
3d96     3d96:	58                   	pop    %rax
3d97     3d97:	fa                   	cli
3d98     3d98:	fb                   	sti
3d99     3d99:	9c                   	pushf
3d9a     3d9a:	58                   	pop    %rax
3d9b     3d9b:	fa                   	cli
3d9c     3d9c:	fb                   	sti
3d9d     3d9d:	9c                   	pushf
3d9e     3d9e:	58                   	pop    %rax
3d9f     3d9f:	fa                   	cli
3da0     3da0:	fb                   	sti
3da1     3da1:	9c                   	pushf
3da2     3da2:	58                   	pop    %rax
3da3     3da3:	fa                   	cli
3da4     3da4:	fb                   	sti
3da5     3da5:	9c                   	pushf
3da6     3da6:	58                   	pop    %rax
3da7     3da7:	fa                   	cli
3da8     3da8:	fb                   	sti
3da9     3da9:	9c                   	pushf
3daa     3daa:	58                   	pop    %rax
3dab     3dab:	fa                   	cli
3dac     3dac:	fb                   	sti
3dad     3dad:	9c                   	pushf
3dae     3dae:	58                   	pop    %rax
3daf     3daf:	fa                   	cli
3db0     3db0:	fb                   	sti
3db1     3db1:	9c                   	pushf
3db2     3db2:	58                   	pop    %rax
3db3     3db3:	fa                   	cli
3db4     3db4:	fb                   	sti
3db5     3db5:	9c                   	pushf
3db6     3db6:	58                   	pop    %rax
3db7     3db7:	fa                   	cli
3db8     3db8:	fb                   	sti
3db9     3db9:	9c                   	pushf
3dba     3dba:	58                   	pop    %rax
3dbb     3dbb:	fa                   	cli
3dbc     3dbc:	fb                   	sti
3dbd     3dbd:	9c                   	pushf
3dbe     3dbe:	58                   	pop    %rax
3dbf     3dbf:	fa                   	cli
3dc0     3dc0:	fb                   	sti
3dc1     3dc1:	9c                   	pushf
3dc2     3dc2:	58                   	pop    %rax
3dc3     3dc3:	fa                   	cli
3dc4     3dc4:	fb                   	sti
3dc5     3dc5:	9c                   	pushf
3dc6     3dc6:	58                   	pop    %rax
3dc7     3dc7:	fa                   	cli
3dc8     3dc8:	fb                   	sti
3dc9     3dc9:	9c                   	pushf
3dca     3dca:	58                   	pop    %rax
3dcb     3dcb:	fa                   	cli
3dcc     3dcc:	fb                   	sti
3dcd     3dcd:	9c                   	pushf
3dce     3dce:	58                   	pop    %rax
3dcf     3dcf:	fa                   	cli
3dd0     3dd0:	fb                   	sti
3dd1     3dd1:	9c                   	pushf
3dd2     3dd2:	58                   	pop    %rax
3dd3     3dd3:	fa                   	cli
3dd4     3dd4:	fb                   	sti
3dd5     3dd5:	9c                   	pushf
3dd6     3dd6:	58                   	pop    %rax
3dd7     3dd7:	fa                   	cli
3dd8     3dd8:	fb                   	sti
3dd9     3dd9:	9c                   	pushf
3dda     3dda:	58                   	pop    %rax
3ddb     3ddb:	fa                   	cli
3ddc     3ddc:	fb                   	sti
3ddd     3ddd:	9c                   	pushf
3dde     3dde:	58                   	pop    %rax
3ddf     3ddf:	fa                   	cli
3de0     3de0:	fb                   	sti
3de1     3de1:	9c                   	pushf
3de2     3de2:	58                   	pop    %rax
3de3     3de3:	fa                   	cli
3de4     3de4:	fb                   	sti
3de5     3de5:	9c                   	pushf
3de6     3de6:	58                   	pop    %rax
3de7     3de7:	fa                   	cli
3de8     3de8:	fb                   	sti
3de9     3de9:	9c                   	pushf
3dea     3dea:	58                   	pop    %rax
3deb     3deb:	fa                   	cli
3dec     3dec:	fb                   	sti
3ded     3ded:	9c                   	pushf
3dee     3dee:	58                   	pop    %rax
3def     3def:	fa                   	cli
3df0     3df0:	fb                   	sti
3df1     3df1:	9c                   	pushf
3df2     3df2:	58                   	pop    %rax
3df3     3df3:	fa                   	cli
3df4     3df4:	fb                   	sti
3df5     3df5:	9c                   	pushf
3df6     3df6:	58                   	pop    %rax
3df7     3df7:	fa                   	cli
3df8     3df8:	fb                   	sti
3df9     3df9:	9c                   	pushf
3dfa     3dfa:	58                   	pop    %rax
3dfb     3dfb:	fa                   	cli
3dfc     3dfc:	fb                   	sti
3dfd     3dfd:	9c                   	pushf
3dfe     3dfe:	58                   	pop    %rax
3dff     3dff:	fa                   	cli
3e00     3e00:	fb                   	sti
3e01     3e01:	9c                   	pushf
3e02     3e02:	58                   	pop    %rax
3e03     3e03:	fa                   	cli
3e04     3e04:	fb                   	sti
3e05     3e05:	9c                   	pushf
3e06     3e06:	58                   	pop    %rax
3e07     3e07:	fa                   	cli
3e08     3e08:	fb                   	sti
3e09     3e09:	9c                   	pushf
3e0a     3e0a:	58                   	pop    %rax
3e0b     3e0b:	fa                   	cli
3e0c     3e0c:	fb                   	sti
3e0d     3e0d:	9c                   	pushf
3e0e     3e0e:	58                   	pop    %rax
3e0f     3e0f:	fa                   	cli
3e10     3e10:	fb                   	sti
3e11     3e11:	9c                   	pushf
3e12     3e12:	58                   	pop    %rax
3e13     3e13:	fa                   	cli
3e14     3e14:	fb                   	sti
3e15     3e15:	9c                   	pushf
3e16     3e16:	58                   	pop    %rax
3e17     3e17:	fa                   	cli
3e18     3e18:	fb                   	sti
3e19     3e19:	9c                   	pushf
3e1a     3e1a:	58                   	pop    %rax
3e1b     3e1b:	fa                   	cli
3e1c     3e1c:	fb                   	sti
3e1d     3e1d:	9c                   	pushf
3e1e     3e1e:	58                   	pop    %rax
3e1f     3e1f:	fa                   	cli
3e20     3e20:	fb                   	sti
3e21     3e21:	9c                   	pushf
3e22     3e22:	58                   	pop    %rax
3e23     3e23:	fa                   	cli
3e24     3e24:	fb                   	sti
3e25     3e25:	9c                   	pushf
3e26     3e26:	58                   	pop    %rax
3e27     3e27:	fa                   	cli
3e28     3e28:	fb                   	sti
3e29     3e29:	9c                   	pushf
3e2a     3e2a:	58                   	pop    %rax
3e2b     3e2b:	fa                   	cli
3e2c     3e2c:	fb                   	sti
3e2d     3e2d:	9c                   	pushf
3e2e     3e2e:	58                   	pop    %rax
3e2f     3e2f:	fa                   	cli
3e30     3e30:	fb                   	sti
3e31     3e31:	9c                   	pushf
3e32     3e32:	58                   	pop    %rax
3e33     3e33:	fa                   	cli
3e34     3e34:	fb                   	sti
3e35     3e35:	9c                   	pushf
3e36     3e36:	58                   	pop    %rax
3e37     3e37:	fa                   	cli
3e38     3e38:	fb                   	sti
3e39     3e39:	9c                   	pushf
3e3a     3e3a:	58                   	pop    %rax
3e3b     3e3b:	fa                   	cli
3e3c     3e3c:	fb                   	sti
3e3d     3e3d:	9c                   	pushf
3e3e     3e3e:	58                   	pop    %rax
3e3f     3e3f:	fa                   	cli
3e40     3e40:	fb                   	sti
3e41     3e41:	9c                   	pushf
3e42     3e42:	58                   	pop    %rax
3e43     3e43:	fa                   	cli
3e44     3e44:	fb                   	sti
3e45     3e45:	9c                   	pushf
3e46     3e46:	58                   	pop    %rax
3e47     3e47:	fa                   	cli
3e48     3e48:	fb                   	sti
3e49     3e49:	9c                   	pushf
3e4a     3e4a:	58                   	pop    %rax
3e4b     3e4b:	fa                   	cli
3e4c     3e4c:	fb                   	sti
3e4d     3e4d:	9c                   	pushf
3e4e     3e4e:	58                   	pop    %rax
3e4f     3e4f:	fa                   	cli
3e50     3e50:	fb                   	sti
3e51     3e51:	9c                   	pushf
3e52     3e52:	58                   	pop    %rax
3e53     3e53:	fa                   	cli
3e54     3e54:	fb                   	sti
3e55     3e55:	9c                   	pushf
3e56     3e56:	58                   	pop    %rax
3e57     3e57:	fa                   	cli
3e58     3e58:	fb                   	sti
3e59     3e59:	9c                   	pushf
3e5a     3e5a:	58                   	pop    %rax
3e5b     3e5b:	fa                   	cli
3e5c     3e5c:	fb                   	sti
3e5d     3e5d:	9c                   	pushf
3e5e     3e5e:	58                   	pop    %rax
3e5f     3e5f:	fa                   	cli
3e60     3e60:	fb                   	sti
3e61     3e61:	9c                   	pushf
3e62     3e62:	58                   	pop    %rax
3e63     3e63:	fa                   	cli
3e64     3e64:	fb                   	sti
3e65     3e65:	9c                   	pushf
3e66     3e66:	58                   	pop    %rax
3e67     3e67:	fa                   	cli
3e68     3e68:	fb                   	sti
3e69     3e69:	9c                   	pushf
3e6a     3e6a:	58                   	pop    %rax
3e6b     3e6b:	fa                   	cli
3e6c     3e6c:	fb                   	sti
3e6d     3e6d:	9c                   	pushf
3e6e     3e6e:	58                   	pop    %rax
3e6f     3e6f:	fa                   	cli
3e70     3e70:	fb                   	sti
3e71     3e71:	9c                   	pushf
3e72     3e72:	58                   	pop    %rax
3e73     3e73:	fa                   	cli
3e74     3e74:	fb                   	sti
3e75     3e75:	9c                   	pushf
3e76     3e76:	58                   	pop    %rax
3e77     3e77:	fa                   	cli
3e78     3e78:	fb                   	sti
3e79     3e79:	9c                   	pushf
3e7a     3e7a:	58                   	pop    %rax
3e7b     3e7b:	fa                   	cli
3e7c     3e7c:	fb                   	sti
3e7d     3e7d:	9c                   	pushf
3e7e     3e7e:	58                   	pop    %rax
3e7f     3e7f:	fa                   	cli
3e80     3e80:	fb                   	sti
3e81     3e81:	9c                   	pushf
3e82     3e82:	58                   	pop    %rax
3e83     3e83:	fa                   	cli
3e84     3e84:	fb                   	sti
3e85     3e85:	9c                   	pushf
3e86     3e86:	58                   	pop    %rax
3e87     3e87:	fa                   	cli
3e88     3e88:	fb                   	sti
3e89     3e89:	9c                   	pushf
3e8a     3e8a:	58                   	pop    %rax
3e8b     3e8b:	fa                   	cli
3e8c     3e8c:	fb                   	sti
3e8d     3e8d:	9c                   	pushf
3e8e     3e8e:	58                   	pop    %rax
3e8f     3e8f:	fa                   	cli
3e90     3e90:	fb                   	sti
3e91     3e91:	9c                   	pushf
3e92     3e92:	58                   	pop    %rax
3e93     3e93:	fa                   	cli
3e94     3e94:	fb                   	sti
3e95     3e95:	9c                   	pushf
3e96     3e96:	58                   	pop    %rax
3e97     3e97:	fa                   	cli
3e98     3e98:	fb                   	sti
3e99     3e99:	9c                   	pushf
3e9a     3e9a:	58                   	pop    %rax
3e9b     3e9b:	fa                   	cli
3e9c     3e9c:	fb                   	sti
3e9d     3e9d:	9c                   	pushf
3e9e     3e9e:	58                   	pop    %rax
3e9f     3e9f:	fa                   	cli
3ea0     3ea0:	fb                   	sti
3ea1     3ea1:	9c                   	pushf
3ea2     3ea2:	58                   	pop    %rax
3ea3     3ea3:	fa                   	cli
3ea4     3ea4:	fb                   	sti
3ea5     3ea5:	9c                   	pushf
3ea6     3ea6:	58                   	pop    %rax
3ea7     3ea7:	fa                   	cli
3ea8     3ea8:	fb                   	sti
3ea9     3ea9:	9c                   	pushf
3eaa     3eaa:	58                   	pop    %rax
3eab     3eab:	fa                   	cli
3eac     3eac:	fb                   	sti
3ead     3ead:	9c                   	pushf
3eae     3eae:	58                   	pop    %rax
3eaf     3eaf:	fa                   	cli
3eb0     3eb0:	fb                   	sti
3eb1     3eb1:	9c                   	pushf
3eb2     3eb2:	58                   	pop    %rax
3eb3     3eb3:	fa                   	cli
3eb4     3eb4:	fb                   	sti
3eb5     3eb5:	9c                   	pushf
3eb6     3eb6:	58                   	pop    %rax
3eb7     3eb7:	fa                   	cli
3eb8     3eb8:	fb                   	sti
3eb9     3eb9:	9c                   	pushf
3eba     3eba:	58                   	pop    %rax
3ebb     3ebb:	fa                   	cli
3ebc     3ebc:	fb                   	sti
3ebd     3ebd:	9c                   	pushf
3ebe     3ebe:	58                   	pop    %rax
3ebf     3ebf:	fa                   	cli
3ec0     3ec0:	fb                   	sti
3ec1     3ec1:	9c                   	pushf
3ec2     3ec2:	58                   	pop    %rax
3ec3     3ec3:	fa                   	cli
3ec4     3ec4:	fb                   	sti
3ec5     3ec5:	9c                   	pushf
3ec6     3ec6:	58                   	pop    %rax
3ec7     3ec7:	fa                   	cli
3ec8     3ec8:	fb                   	sti
3ec9     3ec9:	9c                   	pushf
3eca     3eca:	58                   	pop    %rax
3ecb     3ecb:	fa                   	cli
3ecc     3ecc:	fb                   	sti
3ecd     3ecd:	9c                   	pushf
3ece     3ece:	58                   	pop    %rax
3ecf     3ecf:	fa                   	cli
3ed0     3ed0:	fb                   	sti
3ed1     3ed1:	9c                   	pushf
3ed2     3ed2:	58                   	pop    %rax
3ed3     3ed3:	fa                   	cli
3ed4     3ed4:	fb                   	sti
3ed5     3ed5:	9c                   	pushf
3ed6     3ed6:	58                   	pop    %rax
3ed7     3ed7:	fa                   	cli
3ed8     3ed8:	fb                   	sti
3ed9     3ed9:	9c                   	pushf
3eda     3eda:	58                   	pop    %rax
3edb     3edb:	fa                   	cli
3edc     3edc:	fb                   	sti
3edd     3edd:	9c                   	pushf
3ede     3ede:	58                   	pop    %rax
3edf     3edf:	fa                   	cli
3ee0     3ee0:	fb                   	sti
3ee1     3ee1:	9c                   	pushf
3ee2     3ee2:	58                   	pop    %rax
3ee3     3ee3:	fa                   	cli
3ee4     3ee4:	fb                   	sti
3ee5     3ee5:	9c                   	pushf
3ee6     3ee6:	58                   	pop    %rax
3ee7     3ee7:	fa                   	cli
3ee8     3ee8:	fb                   	sti
3ee9     3ee9:	9c                   	pushf
3eea     3eea:	58                   	pop    %rax
3eeb     3eeb:	fa                   	cli
3eec     3eec:	fb                   	sti
3eed     3eed:	9c                   	pushf
3eee     3eee:	58                   	pop    %rax
3eef     3eef:	fa                   	cli
3ef0     3ef0:	fb                   	sti
3ef1     3ef1:	9c                   	pushf
3ef2     3ef2:	58                   	pop    %rax
3ef3     3ef3:	fa                   	cli
3ef4     3ef4:	fb                   	sti
3ef5     3ef5:	9c                   	pushf
3ef6     3ef6:	58                   	pop    %rax
3ef7     3ef7:	fa                   	cli
3ef8     3ef8:	fb                   	sti
3ef9     3ef9:	9c                   	pushf
3efa     3efa:	58                   	pop    %rax
3efb     3efb:	fa                   	cli
3efc     3efc:	fb                   	sti
3efd     3efd:	9c                   	pushf
3efe     3efe:	58                   	pop    %rax
3eff     3eff:	fa                   	cli
3f00     3f00:	fb                   	sti
3f01     3f01:	9c                   	pushf
3f02     3f02:	58                   	pop    %rax
3f03     3f03:	fa                   	cli
3f04     3f04:	fb                   	sti
3f05     3f05:	9c                   	pushf
3f06     3f06:	58                   	pop    %rax
3f07     3f07:	fa                   	cli
3f08     3f08:	fb                   	sti
3f09     3f09:	9c                   	pushf
3f0a     3f0a:	58                   	pop    %rax
3f0b     3f0b:	fa                   	cli
3f0c     3f0c:	fb                   	sti
3f0d     3f0d:	9c                   	pushf
3f0e     3f0e:	58                   	pop    %rax
3f0f     3f0f:	fb                   	sti
3f10     3f10:	9c                   	pushf
3f11     3f11:	58                   	pop    %rax
3f12     3f12:	fa                   	cli
3f13     3f13:	9c                   	pushf
3f14     3f14:	58                   	pop    %rax
3f15     3f15:	fa                   	cli
3f16     3f16:	9c                   	pushf
3f17     3f17:	58                   	pop    %rax
3f18     3f18:	fa                   	cli
3f19     3f19:	fb                   	sti
3f1a     3f1a:	9c                   	pushf
3f1b     3f1b:	58                   	pop    %rax
3f1c     3f1c:	fa                   	cli
3f1d     3f1d:	9c                   	pushf
3f1e     3f1e:	58                   	pop    %rax
3f1f     3f1f:	fa                   	cli
3f20     3f20:	9c                   	pushf
3f21     3f21:	58                   	pop    %rax
3f22     3f22:	fa                   	cli
3f23     3f23:	9c                   	pushf
3f24     3f24:	58                   	pop    %rax
3f25     3f25:	fa                   	cli
3f26     3f26:	9c                   	pushf
3f27     3f27:	58                   	pop    %rax
3f28     3f28:	fa                   	cli
3f29     3f29:	9c                   	pushf
3f2a     3f2a:	58                   	pop    %rax
3f2b     3f2b:	fa                   	cli
3f2c     3f2c:	9c                   	pushf
3f2d     3f2d:	58                   	pop    %rax
3f2e     3f2e:	fa                   	cli
3f2f     3f2f:	9c                   	pushf
3f30     3f30:	58                   	pop    %rax
3f31     3f31:	fa                   	cli
3f32     3f32:	9c                   	pushf
3f33     3f33:	58                   	pop    %rax
3f34     3f34:	fa                   	cli
3f35     3f35:	9c                   	pushf
3f36     3f36:	58                   	pop    %rax
3f37     3f37:	fa                   	cli
3f38     3f38:	fb                   	sti
3f39     3f39:	9c                   	pushf
3f3a     3f3a:	58                   	pop    %rax
3f3b     3f3b:	fa                   	cli
3f3c     3f3c:	fb                   	sti
3f3d     3f3d:	9c                   	pushf
3f3e     3f3e:	58                   	pop    %rax
3f3f     3f3f:	fa                   	cli
3f40     3f40:	9c                   	pushf
3f41     3f41:	58                   	pop    %rax
3f42     3f42:	fa                   	cli
3f43     3f43:	9c                   	pushf
3f44     3f44:	58                   	pop    %rax
3f45     3f45:	fa                   	cli
3f46     3f46:	fb                   	sti
3f47     3f47:	9c                   	pushf
3f48     3f48:	58                   	pop    %rax
3f49     3f49:	fa                   	cli
3f4a     3f4a:	fb                   	sti
3f4b     3f4b:	9c                   	pushf
3f4c     3f4c:	58                   	pop    %rax
3f4d     3f4d:	fa                   	cli
3f4e     3f4e:	fb                   	sti
3f4f     3f4f:	9c                   	pushf
3f50     3f50:	58                   	pop    %rax
3f51     3f51:	fa                   	cli
3f52     3f52:	fb                   	sti
3f53     3f53:	9c                   	pushf
3f54     3f54:	58                   	pop    %rax
3f55     3f55:	9c                   	pushf
3f56     3f56:	58                   	pop    %rax
3f57     3f57:	fa                   	cli
3f58     3f58:	9c                   	pushf
3f59     3f59:	58                   	pop    %rax
3f5a     3f5a:	fb                   	sti
3f5b     3f5b:	9c                   	pushf
3f5c     3f5c:	58                   	pop    %rax
3f5d     3f5d:	fa                   	cli
3f5e     3f5e:	9c                   	pushf
3f5f     3f5f:	58                   	pop    %rax
3f60     3f60:	fb                   	sti
3f61     3f61:	9c                   	pushf
3f62     3f62:	58                   	pop    %rax
3f63     3f63:	9c                   	pushf
3f64     3f64:	58                   	pop    %rax
3f65     3f65:	fa                   	cli
3f66     3f66:	9c                   	pushf
3f67     3f67:	58                   	pop    %rax
3f68     3f68:	fb                   	sti
3f69     3f69:	9c                   	pushf
3f6a     3f6a:	58                   	pop    %rax
3f6b     3f6b:	fa                   	cli
3f6c     3f6c:	9c                   	pushf
3f6d     3f6d:	58                   	pop    %rax
3f6e     3f6e:	fb                   	sti
3f6f     3f6f:	9c                   	pushf
3f70     3f70:	58                   	pop    %rax
3f71     3f71:	fa                   	cli
3f72     3f72:	9c                   	pushf
3f73     3f73:	58                   	pop    %rax
3f74     3f74:	fb                   	sti
3f75     3f75:	48 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbp
3f7f     3f7f:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
3f89     3f89:	0f 01 cb             	stac
3f8c     3f8c:	0f ae e8             	lfence
3f8f     3f8f:	0f 01 ca             	clac
3f92     3f92:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
3f9c     3f9c:	49 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r13
3fa6     3fa6:	0f 01 cb             	stac
3fa9     3fa9:	0f ae e8             	lfence
3fac     3fac:	0f 01 ca             	clac
3faf     3faf:	9c                   	pushf
3fb0     3fb0:	58                   	pop    %rax
3fb1     3fb1:	fa                   	cli
3fb2     3fb2:	9c                   	pushf
3fb3     3fb3:	58                   	pop    %rax
3fb4     3fb4:	fb                   	sti
3fb5     3fb5:	9c                   	pushf
3fb6     3fb6:	58                   	pop    %rax
3fb7     3fb7:	fa                   	cli
3fb8     3fb8:	fb                   	sti
3fb9     3fb9:	9c                   	pushf
3fba     3fba:	58                   	pop    %rax
3fbb     3fbb:	fa                   	cli
3fbc     3fbc:	9c                   	pushf
3fbd     3fbd:	58                   	pop    %rax
3fbe     3fbe:	fb                   	sti
3fbf     3fbf:	9c                   	pushf
3fc0     3fc0:	58                   	pop    %rax
3fc1     3fc1:	fa                   	cli
3fc2     3fc2:	fb                   	sti
3fc3     3fc3:	9c                   	pushf
3fc4     3fc4:	58                   	pop    %rax
3fc5     3fc5:	fa                   	cli
3fc6     3fc6:	fb                   	sti
3fc7     3fc7:	9c                   	pushf
3fc8     3fc8:	5b                   	pop    %rbx
3fc9     3fc9:	0f 01 ca             	clac
3fcc     3fcc:	53                   	push   %rbx
3fcd     3fcd:	9d                   	popf
3fce     3fce:	9c                   	pushf
3fcf     3fcf:	41 5d                	pop    %r13
3fd1     3fd1:	0f 01 ca             	clac
3fd4     3fd4:	41 55                	push   %r13
3fd6     3fd6:	9d                   	popf
3fd7     3fd7:	0f 09                	wbinvd
3fd9     3fd9:	9c                   	pushf
3fda     3fda:	58                   	pop    %rax
3fdb     3fdb:	fa                   	cli
3fdc     3fdc:	9c                   	pushf
3fdd     3fdd:	58                   	pop    %rax
3fde     3fde:	fb                   	sti
3fdf     3fdf:	9c                   	pushf
3fe0     3fe0:	58                   	pop    %rax
3fe1     3fe1:	fb                   	sti
3fe2     3fe2:	9c                   	pushf
3fe3     3fe3:	58                   	pop    %rax
3fe4     3fe4:	fa                   	cli
3fe5     3fe5:	9c                   	pushf
3fe6     3fe6:	58                   	pop    %rax
3fe7     3fe7:	fb                   	sti
3fe8     3fe8:	9c                   	pushf
3fe9     3fe9:	58                   	pop    %rax
3fea     3fea:	fa                   	cli
3feb     3feb:	9c                   	pushf
3fec     3fec:	58                   	pop    %rax
3fed     3fed:	fb                   	sti
3fee     3fee:	9c                   	pushf
3fef     3fef:	58                   	pop    %rax
3ff0     3ff0:	fb                   	sti
3ff1     3ff1:	9c                   	pushf
3ff2     3ff2:	58                   	pop    %rax
3ff3     3ff3:	fa                   	cli
3ff4     3ff4:	9c                   	pushf
3ff5     3ff5:	58                   	pop    %rax
3ff6     3ff6:	fb                   	sti
3ff7     3ff7:	9c                   	pushf
3ff8     3ff8:	58                   	pop    %rax
3ff9     3ff9:	fa                   	cli
3ffa     3ffa:	9c                   	pushf
3ffb     3ffb:	58                   	pop    %rax
3ffc     3ffc:	fb                   	sti
3ffd     3ffd:	e9 00 00 00 00       	jmp    4002 <.altinstr_replacement+0x4002>	3ffe: R_X86_64_PC32	.text+0x2806212
4002     4002:	e9 00 00 00 00       	jmp    4007 <.altinstr_replacement+0x4007>	4003: R_X86_64_PC32	.text+0x2806428
4007     4007:	0f 01 cb             	stac
400a     400a:	0f 01 ca             	clac
400d     400d:	0f 01 cb             	stac
4010     4010:	0f 01 ca             	clac
4013     4013:	e8 00 00 00 00       	call   4018 <.altinstr_replacement+0x4018>	4014: R_X86_64_PLT32	copy_user_generic_string-0x4
4018     4018:	e8 00 00 00 00       	call   401d <.altinstr_replacement+0x401d>	4019: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
401d     401d:	0f 01 cb             	stac
4020     4020:	0f 01 cb             	stac
4023     4023:	0f 01 ca             	clac
4026     4026:	0f 01 cb             	stac
4029     4029:	0f 01 ca             	clac
402c     402c:	0f 01 ca             	clac
402f     402f:	0f 01 ca             	clac
4032     4032:	0f 01 ca             	clac
4035     4035:	0f 01 cb             	stac
4038     4038:	0f 01 ca             	clac
403b     403b:	0f ae e8             	lfence
403e     403e:	0f 31                	rdtsc
4040     4040:	0f 01 f9             	rdtscp
4043     4043:	0f ae e8             	lfence
4046     4046:	0f 31                	rdtsc
4048     4048:	0f 01 f9             	rdtscp
404b     404b:	0f ae e8             	lfence
404e     404e:	0f 31                	rdtsc
4050     4050:	0f 01 f9             	rdtscp
4053     4053:	0f ae e8             	lfence
4056     4056:	0f 31                	rdtsc
4058     4058:	0f 01 f9             	rdtscp
405b     405b:	48 ba 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rdx
4065     4065:	0f 01 cb             	stac
4068     4068:	0f 01 ca             	clac
406b     406b:	48 ba ff ef ff ff ff ff ff 00 	movabs $0xffffffffffefff,%rdx
4075     4075:	0f 01 cb             	stac
4078     4078:	0f 01 ca             	clac
407b     407b:	48 ba fd ef ff ff ff ff ff 00 	movabs $0xffffffffffeffd,%rdx
4085     4085:	0f 01 cb             	stac
4088     4088:	0f 01 ca             	clac
408b     408b:	48 ba f9 ef ff ff ff ff ff 00 	movabs $0xffffffffffeff9,%rdx
4095     4095:	0f 01 cb             	stac
4098     4098:	0f 01 ca             	clac
409b     409b:	0f 01 cb             	stac
409e     409e:	0f ae e8             	lfence
40a1     40a1:	0f 01 ca             	clac
40a4     40a4:	0f 01 cb             	stac
40a7     40a7:	0f ae e8             	lfence
40aa     40aa:	0f 01 ca             	clac
40ad     40ad:	0f 01 cb             	stac
40b0     40b0:	0f ae e8             	lfence
40b3     40b3:	0f 01 ca             	clac
40b6     40b6:	0f 01 cb             	stac
40b9     40b9:	0f ae e8             	lfence
40bc     40bc:	0f 01 ca             	clac
40bf     40bf:	0f 01 ca             	clac
40c2     40c2:	e8 00 00 00 00       	call   40c7 <.altinstr_replacement+0x40c7>	40c3: R_X86_64_PLT32	copy_user_generic_string-0x4
40c7     40c7:	e8 00 00 00 00       	call   40cc <.altinstr_replacement+0x40cc>	40c8: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
40cc     40cc:	e9 00 00 00 00       	jmp    40d1 <.altinstr_replacement+0x40d1>	40cd: R_X86_64_PC32	.noinstr.text+0xabcc
40d1     40d1:	e9 00 00 00 00       	jmp    40d6 <.altinstr_replacement+0x40d6>	40d2: R_X86_64_PC32	.text+0x280cf09
40d6     40d6:	e9 00 00 00 00       	jmp    40db <.altinstr_replacement+0x40db>	40d7: R_X86_64_PC32	.text+0x280cf5c
40db     40db:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
40e5     40e5:	0f 01 cb             	stac
40e8     40e8:	0f 01 ca             	clac
40eb     40eb:	48 bb ff ef ff ff ff ff ff 00 	movabs $0xffffffffffefff,%rbx
40f5     40f5:	0f 01 cb             	stac
40f8     40f8:	0f 01 ca             	clac
40fb     40fb:	48 bb fd ef ff ff ff ff ff 00 	movabs $0xffffffffffeffd,%rbx
4105     4105:	0f 01 cb             	stac
4108     4108:	0f 01 ca             	clac
410b     410b:	48 bb f9 ef ff ff ff ff ff 00 	movabs $0xffffffffffeff9,%rbx
4115     4115:	0f 01 cb             	stac
4118     4118:	0f 01 ca             	clac
411b     411b:	0f 01 ca             	clac
411e     411e:	0f ae e8             	lfence
4121     4121:	ff e0                	jmp    *%rax
4123     4123:	cc                   	int3
4124     4124:	ff e0                	jmp    *%rax
4126     4126:	0f ae e8             	lfence
4129     4129:	ff e1                	jmp    *%rcx
412b     412b:	cc                   	int3
412c     412c:	ff e1                	jmp    *%rcx
412e     412e:	0f ae e8             	lfence
4131     4131:	ff e2                	jmp    *%rdx
4133     4133:	cc                   	int3
4134     4134:	ff e2                	jmp    *%rdx
4136     4136:	0f ae e8             	lfence
4139     4139:	ff e3                	jmp    *%rbx
413b     413b:	cc                   	int3
413c     413c:	ff e3                	jmp    *%rbx
413e     413e:	0f ae e8             	lfence
4141     4141:	ff e4                	jmp    *%rsp
4143     4143:	cc                   	int3
4144     4144:	ff e4                	jmp    *%rsp
4146     4146:	0f ae e8             	lfence
4149     4149:	ff e5                	jmp    *%rbp
414b     414b:	cc                   	int3
414c     414c:	ff e5                	jmp    *%rbp
414e     414e:	0f ae e8             	lfence
4151     4151:	ff e6                	jmp    *%rsi
4153     4153:	cc                   	int3
4154     4154:	ff e6                	jmp    *%rsi
4156     4156:	0f ae e8             	lfence
4159     4159:	ff e7                	jmp    *%rdi
415b     415b:	cc                   	int3
415c     415c:	ff e7                	jmp    *%rdi
415e     415e:	0f ae e8             	lfence
4161     4161:	41 ff e0             	jmp    *%r8
4164     4164:	cc                   	int3
4165     4165:	41 ff e0             	jmp    *%r8
4168     4168:	0f ae e8             	lfence
416b     416b:	41 ff e1             	jmp    *%r9
416e     416e:	cc                   	int3
416f     416f:	41 ff e1             	jmp    *%r9
4172     4172:	0f ae e8             	lfence
4175     4175:	41 ff e2             	jmp    *%r10
4178     4178:	cc                   	int3
4179     4179:	41 ff e2             	jmp    *%r10
417c     417c:	0f ae e8             	lfence
417f     417f:	41 ff e3             	jmp    *%r11
4182     4182:	cc                   	int3
4183     4183:	41 ff e3             	jmp    *%r11
4186     4186:	0f ae e8             	lfence
4189     4189:	41 ff e4             	jmp    *%r12
418c     418c:	cc                   	int3
418d     418d:	41 ff e4             	jmp    *%r12
4190     4190:	0f ae e8             	lfence
4193     4193:	41 ff e5             	jmp    *%r13
4196     4196:	cc                   	int3
4197     4197:	41 ff e5             	jmp    *%r13
419a     419a:	0f ae e8             	lfence
419d     419d:	41 ff e6             	jmp    *%r14
41a0     41a0:	cc                   	int3
41a1     41a1:	41 ff e6             	jmp    *%r14
41a4     41a4:	0f ae e8             	lfence
41a7     41a7:	41 ff e7             	jmp    *%r15
41aa     41aa:	cc                   	int3
41ab     41ab:	41 ff e7             	jmp    *%r15
41ae     41ae:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
41b8     41b8:	e8 00 00 00 00       	call   41bd <.altinstr_replacement+0x41bd>	41b9: R_X86_64_PLT32	copy_user_generic_string-0x4
41bd     41bd:	e8 00 00 00 00       	call   41c2 <.altinstr_replacement+0x41c2>	41be: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
41c2     41c2:	66 0f ae 38          	clflushopt (%rax)
41c6     41c6:	66 0f ae 30          	clwb   (%rax)
41ca     41ca:	f3 0f b8 c7          	popcnt %edi,%eax
41ce     41ce:	f3 48 0f b8 c7       	popcnt %rdi,%rax
41d3     41d3:	f3 48 0f b8 c7       	popcnt %rdi,%rax
41d8     41d8:	f3 48 0f b8 c7       	popcnt %rdi,%rax
41dd     41dd:	f3 48 0f b8 c7       	popcnt %rdi,%rax
41e2     41e2:	f3 48 0f b8 c7       	popcnt %rdi,%rax
41e7     41e7:	48 ba 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rdx
41f1     41f1:	49 bf 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r15
41fb     41fb:	e8 00 00 00 00       	call   4200 <.altinstr_replacement+0x4200>	41fc: R_X86_64_PLT32	__x86_indirect_thunk_r12-0x4
4200     4200:	0f ae e8             	lfence
4203     4203:	41 ff d4             	call   *%r12
4206     4206:	9c                   	pushf
4207     4207:	58                   	pop    %rax
4208     4208:	fa                   	cli
4209     4209:	fb                   	sti
420a     420a:	e9 00 00 00 00       	jmp    420f <.altinstr_replacement+0x420f>	420b: R_X86_64_PC32	.init.text+0x19a049
420f     420f:	e9 00 00 00 00       	jmp    4214 <.altinstr_replacement+0x4214>	4210: R_X86_64_PC32	.text+0x2bd5dc2
4214     4214:	e9 00 00 00 00       	jmp    4219 <.altinstr_replacement+0x4219>	4215: R_X86_64_PC32	.text+0x2bd5cee
4219     4219:	fb                   	sti
421a     421a:	9c                   	pushf
421b     421b:	58                   	pop    %rax
421c     421c:	fa                   	cli
421d     421d:	9c                   	pushf
421e     421e:	58                   	pop    %rax
421f     421f:	9c                   	pushf
4220     4220:	58                   	pop    %rax
4221     4221:	9c                   	pushf
4222     4222:	58                   	pop    %rax
4223     4223:	fa                   	cli
4224     4224:	9c                   	pushf
4225     4225:	58                   	pop    %rax
4226     4226:	9c                   	pushf
4227     4227:	58                   	pop    %rax
4228     4228:	0f 30                	wrmsr
422a     422a:	0f 30                	wrmsr
422c     422c:	0f 30                	wrmsr
422e     422e:	9c                   	pushf
422f     422f:	58                   	pop    %rax
4230     4230:	9c                   	pushf
4231     4231:	58                   	pop    %rax
4232     4232:	9c                   	pushf
4233     4233:	58                   	pop    %rax
4234     4234:	9c                   	pushf
4235     4235:	58                   	pop    %rax
4236     4236:	9c                   	pushf
4237     4237:	58                   	pop    %rax
4238     4238:	9c                   	pushf
4239     4239:	58                   	pop    %rax
423a     423a:	9c                   	pushf
423b     423b:	58                   	pop    %rax
423c     423c:	9c                   	pushf
423d     423d:	58                   	pop    %rax
423e     423e:	9c                   	pushf
423f     423f:	58                   	pop    %rax
4240     4240:	9c                   	pushf
4241     4241:	58                   	pop    %rax
4242     4242:	9c                   	pushf
4243     4243:	58                   	pop    %rax
4244     4244:	9c                   	pushf
4245     4245:	58                   	pop    %rax
4246     4246:	9c                   	pushf
4247     4247:	58                   	pop    %rax
4248     4248:	9c                   	pushf
4249     4249:	58                   	pop    %rax
424a     424a:	9c                   	pushf
424b     424b:	58                   	pop    %rax
424c     424c:	e9 00 00 00 00       	jmp    4251 <.altinstr_replacement+0x4251>	424d: R_X86_64_PC32	.text+0x2c777ab
4251     4251:	0f 09                	wbinvd
4253     4253:	9c                   	pushf
4254     4254:	58                   	pop    %rax
4255     4255:	9c                   	pushf
4256     4256:	58                   	pop    %rax
4257     4257:	9c                   	pushf
4258     4258:	58                   	pop    %rax
4259     4259:	9c                   	pushf
425a     425a:	58                   	pop    %rax
425b     425b:	9c                   	pushf
425c     425c:	58                   	pop    %rax
425d     425d:	9c                   	pushf
425e     425e:	58                   	pop    %rax
425f     425f:	9c                   	pushf
4260     4260:	58                   	pop    %rax
4261     4261:	9c                   	pushf
4262     4262:	58                   	pop    %rax
4263     4263:	9c                   	pushf
4264     4264:	58                   	pop    %rax
4265     4265:	9c                   	pushf
4266     4266:	58                   	pop    %rax
4267     4267:	9c                   	pushf
4268     4268:	58                   	pop    %rax
4269     4269:	9c                   	pushf
426a     426a:	58                   	pop    %rax
426b     426b:	9c                   	pushf
426c     426c:	58                   	pop    %rax
426d     426d:	9c                   	pushf
426e     426e:	58                   	pop    %rax
426f     426f:	9c                   	pushf
4270     4270:	58                   	pop    %rax
4271     4271:	9c                   	pushf
4272     4272:	58                   	pop    %rax
4273     4273:	9c                   	pushf
4274     4274:	58                   	pop    %rax
4275     4275:	9c                   	pushf
4276     4276:	58                   	pop    %rax
4277     4277:	9c                   	pushf
4278     4278:	58                   	pop    %rax
4279     4279:	9c                   	pushf
427a     427a:	58                   	pop    %rax
427b     427b:	9c                   	pushf
427c     427c:	58                   	pop    %rax
427d     427d:	9c                   	pushf
427e     427e:	58                   	pop    %rax
427f     427f:	9c                   	pushf
4280     4280:	58                   	pop    %rax
4281     4281:	9c                   	pushf
4282     4282:	58                   	pop    %rax
4283     4283:	9c                   	pushf
4284     4284:	58                   	pop    %rax
4285     4285:	9c                   	pushf
4286     4286:	58                   	pop    %rax
4287     4287:	9c                   	pushf
4288     4288:	58                   	pop    %rax
4289     4289:	9c                   	pushf
428a     428a:	58                   	pop    %rax
428b     428b:	9c                   	pushf
428c     428c:	58                   	pop    %rax
428d     428d:	9c                   	pushf
428e     428e:	58                   	pop    %rax
428f     428f:	9c                   	pushf
4290     4290:	58                   	pop    %rax
4291     4291:	9c                   	pushf
4292     4292:	58                   	pop    %rax
4293     4293:	9c                   	pushf
4294     4294:	58                   	pop    %rax
4295     4295:	9c                   	pushf
4296     4296:	58                   	pop    %rax
4297     4297:	9c                   	pushf
4298     4298:	58                   	pop    %rax
4299     4299:	fa                   	cli
429a     429a:	e9 00 00 00 00       	jmp    429f <.altinstr_replacement+0x429f>	429b: R_X86_64_PC32	.cpuidle.text+0x128d
429f     429f:	0f 09                	wbinvd
42a1     42a1:	e9 00 00 00 00       	jmp    42a6 <.altinstr_replacement+0x42a6>	42a2: R_X86_64_PC32	.text+0x2ccb0a2
42a6     42a6:	0f 09                	wbinvd
42a8     42a8:	e9 00 00 00 00       	jmp    42ad <.altinstr_replacement+0x42ad>	42a9: R_X86_64_PC32	.cpuidle.text+0x145a
42ad     42ad:	0f 09                	wbinvd
42af     42af:	9c                   	pushf
42b0     42b0:	58                   	pop    %rax
42b1     42b1:	fa                   	cli
42b2     42b2:	fb                   	sti
42b3     42b3:	9c                   	pushf
42b4     42b4:	58                   	pop    %rax
42b5     42b5:	fa                   	cli
42b6     42b6:	fb                   	sti
42b7     42b7:	9c                   	pushf
42b8     42b8:	58                   	pop    %rax
42b9     42b9:	9c                   	pushf
42ba     42ba:	58                   	pop    %rax
42bb     42bb:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
42c5     42c5:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
42cf     42cf:	e9 00 00 00 00       	jmp    42d4 <.altinstr_replacement+0x42d4>	42d0: R_X86_64_PC32	.text+0x2cfe5c2
42d4     42d4:	e9 00 00 00 00       	jmp    42d9 <.altinstr_replacement+0x42d9>	42d5: R_X86_64_PC32	.text+0x2cfe4ee
42d9     42d9:	9c                   	pushf
42da     42da:	58                   	pop    %rax
42db     42db:	fa                   	cli
42dc     42dc:	fb                   	sti
42dd     42dd:	9c                   	pushf
42de     42de:	58                   	pop    %rax
42df     42df:	fa                   	cli
42e0     42e0:	9c                   	pushf
42e1     42e1:	58                   	pop    %rax
42e2     42e2:	9c                   	pushf
42e3     42e3:	58                   	pop    %rax
42e4     42e4:	fa                   	cli
42e5     42e5:	9c                   	pushf
42e6     42e6:	58                   	pop    %rax
42e7     42e7:	fb                   	sti
42e8     42e8:	e9 00 00 00 00       	jmp    42ed <.altinstr_replacement+0x42ed>	42e9: R_X86_64_PC32	.text+0x2d059e2
42ed     42ed:	e9 00 00 00 00       	jmp    42f2 <.altinstr_replacement+0x42f2>	42ee: R_X86_64_PC32	.text+0x2d05a05
42f2     42f2:	9c                   	pushf
42f3     42f3:	58                   	pop    %rax
42f4     42f4:	fa                   	cli
42f5     42f5:	9c                   	pushf
42f6     42f6:	58                   	pop    %rax
42f7     42f7:	fb                   	sti
42f8     42f8:	e9 00 00 00 00       	jmp    42fd <.altinstr_replacement+0x42fd>	42f9: R_X86_64_PC32	.init.text+0x1b8c94
42fd     42fd:	e9 00 00 00 00       	jmp    4302 <.altinstr_replacement+0x4302>	42fe: R_X86_64_PC32	.init.text+0x1b8cb4
4302     4302:	f3 0f b8 c7          	popcnt %edi,%eax
4306     4306:	e8 00 00 00 00       	call   430b <.altinstr_replacement+0x430b>	4307: R_X86_64_PLT32	clear_page_rep-0x4
430b     430b:	e8 00 00 00 00       	call   4310 <.altinstr_replacement+0x4310>	430c: R_X86_64_PLT32	clear_page_erms-0x4
4310     4310:	9c                   	pushf
4311     4311:	58                   	pop    %rax
4312     4312:	e8 00 00 00 00       	call   4317 <.altinstr_replacement+0x4317>	4313: R_X86_64_PLT32	clear_page_rep-0x4
4317     4317:	e8 00 00 00 00       	call   431c <.altinstr_replacement+0x431c>	4318: R_X86_64_PLT32	clear_page_erms-0x4
431c     431c:	9c                   	pushf
431d     431d:	58                   	pop    %rax
431e     431e:	9c                   	pushf
431f     431f:	58                   	pop    %rax
4320     4320:	9c                   	pushf
4321     4321:	58                   	pop    %rax
4322     4322:	9c                   	pushf
4323     4323:	58                   	pop    %rax
4324     4324:	e8 00 00 00 00       	call   4329 <.altinstr_replacement+0x4329>	4325: R_X86_64_PLT32	clear_page_rep-0x4
4329     4329:	e8 00 00 00 00       	call   432e <.altinstr_replacement+0x432e>	432a: R_X86_64_PLT32	clear_page_erms-0x4
432e     432e:	9c                   	pushf
432f     432f:	58                   	pop    %rax
4330     4330:	e9 00 00 00 00       	jmp    4335 <.altinstr_replacement+0x4335>	4331: R_X86_64_PC32	.text+0x2e61848
4335     4335:	e9 00 00 00 00       	jmp    433a <.altinstr_replacement+0x433a>	4336: R_X86_64_PC32	.text+0x2e6189b
433a     433a:	e9 00 00 00 00       	jmp    433f <.altinstr_replacement+0x433f>	433b: R_X86_64_PC32	.text+0x2e67091
433f     433f:	e9 00 00 00 00       	jmp    4344 <.altinstr_replacement+0x4344>	4340: R_X86_64_PC32	.text+0x2e6725d
4344     4344:	0f 01 cb             	stac
4347     4347:	e8 00 00 00 00       	call   434c <.altinstr_replacement+0x434c>	4348: R_X86_64_PLT32	__x86_indirect_thunk_rax-0x4
434c     434c:	0f ae e8             	lfence
434f     434f:	ff d0                	call   *%rax
4351     4351:	0f 01 ca             	clac
4354     4354:	48 ba 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rdx
435e     435e:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
4368     4368:	0f 01 cb             	stac
436b     436b:	e8 00 00 00 00       	call   4370 <.altinstr_replacement+0x4370>	436c: R_X86_64_PLT32	clear_user_erms-0x4
4370     4370:	e8 00 00 00 00       	call   4375 <.altinstr_replacement+0x4375>	4371: R_X86_64_PLT32	clear_user_rep_good-0x4
4375     4375:	e8 00 00 00 00       	call   437a <.altinstr_replacement+0x437a>	4376: R_X86_64_PLT32	clear_user_original-0x4
437a     437a:	0f 01 ca             	clac
437d     437d:	49 be 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r14
4387     4387:	0f 01 cb             	stac
438a     438a:	0f 01 ca             	clac
438d     438d:	48 89 f8             	mov    %rdi,%rax
4390     4390:	f3 0f b8 c7          	popcnt %edi,%eax
4394     4394:	f3 0f b8 c7          	popcnt %edi,%eax
4398     4398:	fb                   	sti
4399     4399:	9c                   	pushf
439a     439a:	58                   	pop    %rax
439b     439b:	fa                   	cli
439c     439c:	9c                   	pushf
439d     439d:	58                   	pop    %rax
439e     439e:	fb                   	sti
439f     439f:	f3 0f b8 c7          	popcnt %edi,%eax
43a3     43a3:	9c                   	pushf
43a4     43a4:	58                   	pop    %rax
43a5     43a5:	fa                   	cli
43a6     43a6:	9c                   	pushf
43a7     43a7:	58                   	pop    %rax
43a8     43a8:	fb                   	sti
43a9     43a9:	9c                   	pushf
43aa     43aa:	58                   	pop    %rax
43ab     43ab:	fa                   	cli
43ac     43ac:	9c                   	pushf
43ad     43ad:	58                   	pop    %rax
43ae     43ae:	fb                   	sti
43af     43af:	9c                   	pushf
43b0     43b0:	58                   	pop    %rax
43b1     43b1:	fa                   	cli
43b2     43b2:	9c                   	pushf
43b3     43b3:	58                   	pop    %rax
43b4     43b4:	fb                   	sti
43b5     43b5:	9c                   	pushf
43b6     43b6:	58                   	pop    %rax
43b7     43b7:	fa                   	cli
43b8     43b8:	9c                   	pushf
43b9     43b9:	58                   	pop    %rax
43ba     43ba:	fb                   	sti
43bb     43bb:	9c                   	pushf
43bc     43bc:	58                   	pop    %rax
43bd     43bd:	fa                   	cli
43be     43be:	9c                   	pushf
43bf     43bf:	58                   	pop    %rax
43c0     43c0:	fb                   	sti
43c1     43c1:	9c                   	pushf
43c2     43c2:	58                   	pop    %rax
43c3     43c3:	fa                   	cli
43c4     43c4:	9c                   	pushf
43c5     43c5:	58                   	pop    %rax
43c6     43c6:	fb                   	sti
43c7     43c7:	9c                   	pushf
43c8     43c8:	58                   	pop    %rax
43c9     43c9:	fa                   	cli
43ca     43ca:	9c                   	pushf
43cb     43cb:	58                   	pop    %rax
43cc     43cc:	fb                   	sti
43cd     43cd:	9c                   	pushf
43ce     43ce:	58                   	pop    %rax
43cf     43cf:	fa                   	cli
43d0     43d0:	9c                   	pushf
43d1     43d1:	58                   	pop    %rax
43d2     43d2:	fb                   	sti
43d3     43d3:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
43dd     43dd:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
43e7     43e7:	49 be 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r14
43f1     43f1:	0f 01 cb             	stac
43f4     43f4:	e8 00 00 00 00       	call   43f9 <.altinstr_replacement+0x43f9>	43f5: R_X86_64_PLT32	clear_user_erms-0x4
43f9     43f9:	e8 00 00 00 00       	call   43fe <.altinstr_replacement+0x43fe>	43fa: R_X86_64_PLT32	clear_user_rep_good-0x4
43fe     43fe:	e8 00 00 00 00       	call   4403 <.altinstr_replacement+0x4403>	43ff: R_X86_64_PLT32	clear_user_original-0x4
4403     4403:	0f 01 ca             	clac
4406     4406:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
4410     4410:	0f 01 cb             	stac
4413     4413:	e8 00 00 00 00       	call   4418 <.altinstr_replacement+0x4418>	4414: R_X86_64_PLT32	clear_user_erms-0x4
4418     4418:	e8 00 00 00 00       	call   441d <.altinstr_replacement+0x441d>	4419: R_X86_64_PLT32	clear_user_rep_good-0x4
441d     441d:	e8 00 00 00 00       	call   4422 <.altinstr_replacement+0x4422>	441e: R_X86_64_PLT32	clear_user_original-0x4
4422     4422:	0f 01 ca             	clac
4425     4425:	e9 00 00 00 00       	jmp    442a <.altinstr_replacement+0x442a>	4426: R_X86_64_PC32	.text+0x3035b06
442a     442a:	e9 00 00 00 00       	jmp    442f <.altinstr_replacement+0x442f>	442b: R_X86_64_PC32	.text+0x3035b72
442f     442f:	e9 00 00 00 00       	jmp    4434 <.altinstr_replacement+0x4434>	4430: R_X86_64_PC32	.text+0x3036e40
4434     4434:	e9 00 00 00 00       	jmp    4439 <.altinstr_replacement+0x4439>	4435: R_X86_64_PC32	.text+0x3036e96
4439     4439:	9c                   	pushf
443a     443a:	58                   	pop    %rax
443b     443b:	fa                   	cli
443c     443c:	9c                   	pushf
443d     443d:	58                   	pop    %rax
443e     443e:	fb                   	sti
443f     443f:	9c                   	pushf
4440     4440:	58                   	pop    %rax
4441     4441:	fa                   	cli
4442     4442:	fb                   	sti
4443     4443:	fb                   	sti
4444     4444:	9c                   	pushf
4445     4445:	58                   	pop    %rax
4446     4446:	fa                   	cli
4447     4447:	9c                   	pushf
4448     4448:	58                   	pop    %rax
4449     4449:	fb                   	sti
444a     444a:	9c                   	pushf
444b     444b:	58                   	pop    %rax
444c     444c:	fa                   	cli
444d     444d:	9c                   	pushf
444e     444e:	58                   	pop    %rax
444f     444f:	fb                   	sti
4450     4450:	9c                   	pushf
4451     4451:	58                   	pop    %rax
4452     4452:	fa                   	cli
4453     4453:	9c                   	pushf
4454     4454:	58                   	pop    %rax
4455     4455:	fb                   	sti
4456     4456:	9c                   	pushf
4457     4457:	58                   	pop    %rax
4458     4458:	fa                   	cli
4459     4459:	9c                   	pushf
445a     445a:	58                   	pop    %rax
445b     445b:	fb                   	sti
445c     445c:	9c                   	pushf
445d     445d:	58                   	pop    %rax
445e     445e:	fa                   	cli
445f     445f:	0f 09                	wbinvd
4461     4461:	f3 0f b8 c7          	popcnt %edi,%eax
4465     4465:	e9 00 00 00 00       	jmp    446a <.altinstr_replacement+0x446a>	4466: R_X86_64_PC32	.text+0x30f03e9
446a     446a:	e9 00 00 00 00       	jmp    446f <.altinstr_replacement+0x446f>	446b: R_X86_64_PC32	.text+0x30f14e8
446f     446f:	e9 00 00 00 00       	jmp    4474 <.altinstr_replacement+0x4474>	4470: R_X86_64_PC32	.text+0x30f1ee1
4474     4474:	e9 00 00 00 00       	jmp    4479 <.altinstr_replacement+0x4479>	4475: R_X86_64_PC32	.text+0x30f1f1a
4479     4479:	e9 00 00 00 00       	jmp    447e <.altinstr_replacement+0x447e>	447a: R_X86_64_PC32	.text+0x3114ff2
447e     447e:	66 0f ae 3b          	clflushopt (%rbx)
4482     4482:	66 0f ae 7d ff       	clflushopt -0x1(%rbp)
4487     4487:	66 0f ae 38          	clflushopt (%rax)
448b     448b:	e9 00 00 00 00       	jmp    4490 <.altinstr_replacement+0x4490>	448c: R_X86_64_PC32	.text+0x31159b1
4490     4490:	e9 00 00 00 00       	jmp    4495 <.altinstr_replacement+0x4495>	4491: R_X86_64_PC32	.text+0x3115b16
4495     4495:	e9 00 00 00 00       	jmp    449a <.altinstr_replacement+0x449a>	4496: R_X86_64_PC32	.text+0x3115bfc
449a     449a:	f3 0f b8 c7          	popcnt %edi,%eax
449e     449e:	f3 0f b8 c7          	popcnt %edi,%eax
44a2     44a2:	f3 0f b8 c7          	popcnt %edi,%eax
44a6     44a6:	f3 48 0f b8 c7       	popcnt %rdi,%rax
44ab     44ab:	f3 0f b8 c7          	popcnt %edi,%eax
44af     44af:	9c                   	pushf
44b0     44b0:	58                   	pop    %rax
44b1     44b1:	fa                   	cli
44b2     44b2:	9c                   	pushf
44b3     44b3:	58                   	pop    %rax
44b4     44b4:	fb                   	sti
44b5     44b5:	49 bf 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r15
44bf     44bf:	0f 01 cb             	stac
44c2     44c2:	e8 00 00 00 00       	call   44c7 <.altinstr_replacement+0x44c7>	44c3: R_X86_64_PLT32	clear_user_erms-0x4
44c7     44c7:	e8 00 00 00 00       	call   44cc <.altinstr_replacement+0x44cc>	44c8: R_X86_64_PLT32	clear_user_rep_good-0x4
44cc     44cc:	e8 00 00 00 00       	call   44d1 <.altinstr_replacement+0x44d1>	44cd: R_X86_64_PLT32	clear_user_original-0x4
44d1     44d1:	0f 01 ca             	clac
44d4     44d4:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
44de     44de:	0f 01 cb             	stac
44e1     44e1:	e8 00 00 00 00       	call   44e6 <.altinstr_replacement+0x44e6>	44e2: R_X86_64_PLT32	clear_user_erms-0x4
44e6     44e6:	e8 00 00 00 00       	call   44eb <.altinstr_replacement+0x44eb>	44e7: R_X86_64_PLT32	clear_user_rep_good-0x4
44eb     44eb:	e8 00 00 00 00       	call   44f0 <.altinstr_replacement+0x44f0>	44ec: R_X86_64_PLT32	clear_user_original-0x4
44f0     44f0:	0f 01 ca             	clac
44f3     44f3:	f3 48 0f b8 c7       	popcnt %rdi,%rax
44f8     44f8:	f3 0f b8 c7          	popcnt %edi,%eax
44fc     44fc:	9c                   	pushf
44fd     44fd:	58                   	pop    %rax
44fe     44fe:	9c                   	pushf
44ff     44ff:	58                   	pop    %rax
4500     4500:	9c                   	pushf
4501     4501:	58                   	pop    %rax
4502     4502:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4507     4507:	f3 48 0f b8 c7       	popcnt %rdi,%rax
450c     450c:	f3 0f b8 c7          	popcnt %edi,%eax
4510     4510:	f3 0f b8 c7          	popcnt %edi,%eax
4514     4514:	e8 00 00 00 00       	call   4519 <.altinstr_replacement+0x4519>	4515: R_X86_64_PLT32	clear_page_rep-0x4
4519     4519:	e8 00 00 00 00       	call   451e <.altinstr_replacement+0x451e>	451a: R_X86_64_PLT32	clear_page_erms-0x4
451e     451e:	0f 09                	wbinvd
4520     4520:	9c                   	pushf
4521     4521:	58                   	pop    %rax
4522     4522:	9c                   	pushf
4523     4523:	58                   	pop    %rax
4524     4524:	49 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r13
452e     452e:	0f 01 cb             	stac
4531     4531:	e8 00 00 00 00       	call   4536 <.altinstr_replacement+0x4536>	4532: R_X86_64_PLT32	clear_user_erms-0x4
4536     4536:	e8 00 00 00 00       	call   453b <.altinstr_replacement+0x453b>	4537: R_X86_64_PLT32	clear_user_rep_good-0x4
453b     453b:	e8 00 00 00 00       	call   4540 <.altinstr_replacement+0x4540>	453c: R_X86_64_PLT32	clear_user_original-0x4
4540     4540:	0f 01 ca             	clac
4543     4543:	9c                   	pushf
4544     4544:	58                   	pop    %rax
4545     4545:	9c                   	pushf
4546     4546:	58                   	pop    %rax
4547     4547:	f3 0f b8 c7          	popcnt %edi,%eax
454b     454b:	f3 0f b8 c7          	popcnt %edi,%eax
454f     454f:	f3 0f b8 c7          	popcnt %edi,%eax
4553     4553:	f3 0f b8 c7          	popcnt %edi,%eax
4557     4557:	f3 0f b8 c7          	popcnt %edi,%eax
455b     455b:	f3 0f b8 c7          	popcnt %edi,%eax
455f     455f:	f3 0f b8 c7          	popcnt %edi,%eax
4563     4563:	f3 0f b8 c7          	popcnt %edi,%eax
4567     4567:	9c                   	pushf
4568     4568:	58                   	pop    %rax
4569     4569:	9c                   	pushf
456a     456a:	58                   	pop    %rax
456b     456b:	e9 00 00 00 00       	jmp    4570 <.altinstr_replacement+0x4570>	456c: R_X86_64_PC32	.text+0x3495db6
4570     4570:	e9 00 00 00 00       	jmp    4575 <.altinstr_replacement+0x4575>	4571: R_X86_64_PC32	.text+0x3495e11
4575     4575:	e9 00 00 00 00       	jmp    457a <.altinstr_replacement+0x457a>	4576: R_X86_64_PC32	.text+0x3496133
457a     457a:	e9 00 00 00 00       	jmp    457f <.altinstr_replacement+0x457f>	457b: R_X86_64_PC32	.text+0x349618e
457f     457f:	f3 0f b8 c7          	popcnt %edi,%eax
4583     4583:	f3 0f b8 c7          	popcnt %edi,%eax
4587     4587:	f3 0f b8 c7          	popcnt %edi,%eax
458b     458b:	f3 0f b8 c7          	popcnt %edi,%eax
458f     458f:	f3 0f b8 c7          	popcnt %edi,%eax
4593     4593:	f3 0f b8 c7          	popcnt %edi,%eax
4597     4597:	f3 0f b8 c7          	popcnt %edi,%eax
459b     459b:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
45a5     45a5:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
45af     45af:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
45b9     45b9:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
45c3     45c3:	48 ba 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rdx
45cd     45cd:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
45d7     45d7:	f3 0f b8 c7          	popcnt %edi,%eax
45db     45db:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
45e5     45e5:	9c                   	pushf
45e6     45e6:	58                   	pop    %rax
45e7     45e7:	fa                   	cli
45e8     45e8:	9c                   	pushf
45e9     45e9:	58                   	pop    %rax
45ea     45ea:	fb                   	sti
45eb     45eb:	9c                   	pushf
45ec     45ec:	58                   	pop    %rax
45ed     45ed:	fa                   	cli
45ee     45ee:	9c                   	pushf
45ef     45ef:	58                   	pop    %rax
45f0     45f0:	fb                   	sti
45f1     45f1:	f3 0f b8 c7          	popcnt %edi,%eax
45f5     45f5:	f3 0f b8 c7          	popcnt %edi,%eax
45f9     45f9:	f3 0f b8 c7          	popcnt %edi,%eax
45fd     45fd:	f3 0f b8 c7          	popcnt %edi,%eax
4601     4601:	f3 0f b8 c7          	popcnt %edi,%eax
4605     4605:	f3 0f b8 c7          	popcnt %edi,%eax
4609     4609:	f3 0f b8 c7          	popcnt %edi,%eax
460d     460d:	f3 0f b8 c7          	popcnt %edi,%eax
4611     4611:	f3 0f b8 c7          	popcnt %edi,%eax
4615     4615:	f3 0f b8 c7          	popcnt %edi,%eax
4619     4619:	e9 00 00 00 00       	jmp    461e <.altinstr_replacement+0x461e>	461a: R_X86_64_PC32	.text+0x3e609fc
461e     461e:	48 89 f8             	mov    %rdi,%rax
4621     4621:	f3 0f b8 c7          	popcnt %edi,%eax
4625     4625:	f3 0f b8 c7          	popcnt %edi,%eax
4629     4629:	f3 0f b8 c7          	popcnt %edi,%eax
462d     462d:	f3 0f b8 c7          	popcnt %edi,%eax
4631     4631:	f3 0f b8 c7          	popcnt %edi,%eax
4635     4635:	f3 0f b8 c7          	popcnt %edi,%eax
4639     4639:	9c                   	pushf
463a     463a:	58                   	pop    %rax
463b     463b:	fa                   	cli
463c     463c:	fb                   	sti
463d     463d:	f3 0f b8 c7          	popcnt %edi,%eax
4641     4641:	9c                   	pushf
4642     4642:	58                   	pop    %rax
4643     4643:	9c                   	pushf
4644     4644:	58                   	pop    %rax
4645     4645:	fa                   	cli
4646     4646:	fb                   	sti
4647     4647:	9c                   	pushf
4648     4648:	58                   	pop    %rax
4649     4649:	fa                   	cli
464a     464a:	9c                   	pushf
464b     464b:	58                   	pop    %rax
464c     464c:	fb                   	sti
464d     464d:	9c                   	pushf
464e     464e:	58                   	pop    %rax
464f     464f:	fa                   	cli
4650     4650:	9c                   	pushf
4651     4651:	58                   	pop    %rax
4652     4652:	fb                   	sti
4653     4653:	9c                   	pushf
4654     4654:	58                   	pop    %rax
4655     4655:	fa                   	cli
4656     4656:	9c                   	pushf
4657     4657:	58                   	pop    %rax
4658     4658:	fb                   	sti
4659     4659:	9c                   	pushf
465a     465a:	58                   	pop    %rax
465b     465b:	fa                   	cli
465c     465c:	fb                   	sti
465d     465d:	9c                   	pushf
465e     465e:	58                   	pop    %rax
465f     465f:	fa                   	cli
4660     4660:	fb                   	sti
4661     4661:	9c                   	pushf
4662     4662:	58                   	pop    %rax
4663     4663:	fa                   	cli
4664     4664:	9c                   	pushf
4665     4665:	58                   	pop    %rax
4666     4666:	fb                   	sti
4667     4667:	9c                   	pushf
4668     4668:	58                   	pop    %rax
4669     4669:	fa                   	cli
466a     466a:	fb                   	sti
466b     466b:	9c                   	pushf
466c     466c:	58                   	pop    %rax
466d     466d:	fa                   	cli
466e     466e:	fb                   	sti
466f     466f:	9c                   	pushf
4670     4670:	58                   	pop    %rax
4671     4671:	fa                   	cli
4672     4672:	fb                   	sti
4673     4673:	f3 0f b8 c7          	popcnt %edi,%eax
4677     4677:	f3 0f b8 c7          	popcnt %edi,%eax
467b     467b:	f3 0f b8 c7          	popcnt %edi,%eax
467f     467f:	f3 0f b8 c7          	popcnt %edi,%eax
4683     4683:	f3 0f b8 c7          	popcnt %edi,%eax
4687     4687:	f3 0f b8 c7          	popcnt %edi,%eax
468b     468b:	f3 0f b8 c7          	popcnt %edi,%eax
468f     468f:	f3 0f b8 c7          	popcnt %edi,%eax
4693     4693:	f3 0f b8 c7          	popcnt %edi,%eax
4697     4697:	f3 48 0f b8 c7       	popcnt %rdi,%rax
469c     469c:	f3 0f b8 c7          	popcnt %edi,%eax
46a0     46a0:	f3 0f b8 c7          	popcnt %edi,%eax
46a4     46a4:	f3 0f b8 c7          	popcnt %edi,%eax
46a8     46a8:	f3 0f b8 c7          	popcnt %edi,%eax
46ac     46ac:	f3 0f b8 c7          	popcnt %edi,%eax
46b0     46b0:	f3 0f b8 c7          	popcnt %edi,%eax
46b4     46b4:	f3 0f b8 c7          	popcnt %edi,%eax
46b8     46b8:	f3 0f b8 c7          	popcnt %edi,%eax
46bc     46bc:	f3 0f b8 c7          	popcnt %edi,%eax
46c0     46c0:	f3 0f b8 c7          	popcnt %edi,%eax
46c4     46c4:	f3 0f b8 c7          	popcnt %edi,%eax
46c8     46c8:	f3 48 0f b8 c7       	popcnt %rdi,%rax
46cd     46cd:	f3 48 0f b8 c7       	popcnt %rdi,%rax
46d2     46d2:	f3 0f b8 c7          	popcnt %edi,%eax
46d6     46d6:	f3 0f b8 c7          	popcnt %edi,%eax
46da     46da:	f3 0f b8 c7          	popcnt %edi,%eax
46de     46de:	f3 0f b8 c7          	popcnt %edi,%eax
46e2     46e2:	f3 0f b8 c7          	popcnt %edi,%eax
46e6     46e6:	f3 0f b8 c7          	popcnt %edi,%eax
46ea     46ea:	f3 0f b8 c7          	popcnt %edi,%eax
46ee     46ee:	f3 0f b8 c7          	popcnt %edi,%eax
46f2     46f2:	f3 0f b8 c7          	popcnt %edi,%eax
46f6     46f6:	f3 0f b8 c7          	popcnt %edi,%eax
46fa     46fa:	f3 0f b8 c7          	popcnt %edi,%eax
46fe     46fe:	f3 0f b8 c7          	popcnt %edi,%eax
4702     4702:	f3 0f b8 c7          	popcnt %edi,%eax
4706     4706:	e9 00 00 00 00       	jmp    470b <.altinstr_replacement+0x470b>	4707: R_X86_64_PC32	.text+0x3f6edbc
470b     470b:	e9 00 00 00 00       	jmp    4710 <.altinstr_replacement+0x4710>	470c: R_X86_64_PC32	.text+0x3f6f132
4710     4710:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
471a     471a:	f3 48 0f b8 c7       	popcnt %rdi,%rax
471f     471f:	e8 00 00 00 00       	call   4724 <.altinstr_replacement+0x4724>	4720: R_X86_64_PLT32	copy_user_generic_string-0x4
4724     4724:	e8 00 00 00 00       	call   4729 <.altinstr_replacement+0x4729>	4725: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
4729     4729:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
4733     4733:	0f 01 cb             	stac
4736     4736:	0f ae e8             	lfence
4739     4739:	0f 01 ca             	clac
473c     473c:	0f 01 ca             	clac
473f     473f:	48 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbp
4749     4749:	e8 00 00 00 00       	call   474e <.altinstr_replacement+0x474e>	474a: R_X86_64_PLT32	copy_user_generic_string-0x4
474e     474e:	e8 00 00 00 00       	call   4753 <.altinstr_replacement+0x4753>	474f: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
4753     4753:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
475d     475d:	e8 00 00 00 00       	call   4762 <.altinstr_replacement+0x4762>	475e: R_X86_64_PLT32	copy_user_generic_string-0x4
4762     4762:	e8 00 00 00 00       	call   4767 <.altinstr_replacement+0x4767>	4763: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
4767     4767:	49 bf 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r15
4771     4771:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
477b     477b:	e8 00 00 00 00       	call   4780 <.altinstr_replacement+0x4780>	477c: R_X86_64_PLT32	copy_user_generic_string-0x4
4780     4780:	e8 00 00 00 00       	call   4785 <.altinstr_replacement+0x4785>	4781: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
4785     4785:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
478f     478f:	0f 01 cb             	stac
4792     4792:	0f ae e8             	lfence
4795     4795:	0f 01 ca             	clac
4798     4798:	e8 00 00 00 00       	call   479d <.altinstr_replacement+0x479d>	4799: R_X86_64_PLT32	copy_user_generic_string-0x4
479d     479d:	e8 00 00 00 00       	call   47a2 <.altinstr_replacement+0x47a2>	479e: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
47a2     47a2:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
47ac     47ac:	e8 00 00 00 00       	call   47b1 <.altinstr_replacement+0x47b1>	47ad: R_X86_64_PLT32	copy_user_generic_string-0x4
47b1     47b1:	e8 00 00 00 00       	call   47b6 <.altinstr_replacement+0x47b6>	47b2: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
47b6     47b6:	e8 00 00 00 00       	call   47bb <.altinstr_replacement+0x47bb>	47b7: R_X86_64_PLT32	copy_user_generic_string-0x4
47bb     47bb:	e8 00 00 00 00       	call   47c0 <.altinstr_replacement+0x47c0>	47bc: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
47c0     47c0:	e8 00 00 00 00       	call   47c5 <.altinstr_replacement+0x47c5>	47c1: R_X86_64_PLT32	copy_user_generic_string-0x4
47c5     47c5:	e8 00 00 00 00       	call   47ca <.altinstr_replacement+0x47ca>	47c6: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
47ca     47ca:	49 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r13
47d4     47d4:	49 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r13
47de     47de:	49 be 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r14
47e8     47e8:	0f 01 cb             	stac
47eb     47eb:	0f ae e8             	lfence
47ee     47ee:	0f 01 ca             	clac
47f1     47f1:	0f 01 ca             	clac
47f4     47f4:	e8 00 00 00 00       	call   47f9 <.altinstr_replacement+0x47f9>	47f5: R_X86_64_PLT32	copy_user_generic_string-0x4
47f9     47f9:	e8 00 00 00 00       	call   47fe <.altinstr_replacement+0x47fe>	47fa: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
47fe     47fe:	e8 00 00 00 00       	call   4803 <.altinstr_replacement+0x4803>	47ff: R_X86_64_PLT32	copy_user_generic_string-0x4
4803     4803:	e8 00 00 00 00       	call   4808 <.altinstr_replacement+0x4808>	4804: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
4808     4808:	9c                   	pushf
4809     4809:	58                   	pop    %rax
480a     480a:	fa                   	cli
480b     480b:	fb                   	sti
480c     480c:	9c                   	pushf
480d     480d:	58                   	pop    %rax
480e     480e:	f3 0f b8 c7          	popcnt %edi,%eax
4812     4812:	9c                   	pushf
4813     4813:	58                   	pop    %rax
4814     4814:	9c                   	pushf
4815     4815:	58                   	pop    %rax
4816     4816:	9c                   	pushf
4817     4817:	58                   	pop    %rax
4818     4818:	9c                   	pushf
4819     4819:	58                   	pop    %rax
481a     481a:	9c                   	pushf
481b     481b:	58                   	pop    %rax
481c     481c:	9c                   	pushf
481d     481d:	58                   	pop    %rax
481e     481e:	9c                   	pushf
481f     481f:	58                   	pop    %rax
4820     4820:	9c                   	pushf
4821     4821:	58                   	pop    %rax
4822     4822:	9c                   	pushf
4823     4823:	58                   	pop    %rax
4824     4824:	9c                   	pushf
4825     4825:	58                   	pop    %rax
4826     4826:	9c                   	pushf
4827     4827:	58                   	pop    %rax
4828     4828:	9c                   	pushf
4829     4829:	58                   	pop    %rax
482a     482a:	9c                   	pushf
482b     482b:	58                   	pop    %rax
482c     482c:	f3 0f b8 c7          	popcnt %edi,%eax
4830     4830:	f3 0f b8 c7          	popcnt %edi,%eax
4834     4834:	f3 0f b8 c7          	popcnt %edi,%eax
4838     4838:	f3 0f b8 c7          	popcnt %edi,%eax
483c     483c:	9c                   	pushf
483d     483d:	58                   	pop    %rax
483e     483e:	fa                   	cli
483f     483f:	fb                   	sti
4840     4840:	9c                   	pushf
4841     4841:	58                   	pop    %rax
4842     4842:	fa                   	cli
4843     4843:	9c                   	pushf
4844     4844:	58                   	pop    %rax
4845     4845:	fa                   	cli
4846     4846:	fb                   	sti
4847     4847:	9c                   	pushf
4848     4848:	58                   	pop    %rax
4849     4849:	fa                   	cli
484a     484a:	fb                   	sti
484b     484b:	f3 0f b8 c7          	popcnt %edi,%eax
484f     484f:	f3 0f b8 c7          	popcnt %edi,%eax
4853     4853:	f3 0f b8 c7          	popcnt %edi,%eax
4857     4857:	f3 0f b8 c7          	popcnt %edi,%eax
485b     485b:	f3 0f b8 c7          	popcnt %edi,%eax
485f     485f:	f3 0f b8 c7          	popcnt %edi,%eax
4863     4863:	f3 0f b8 c7          	popcnt %edi,%eax
4867     4867:	f3 0f b8 c7          	popcnt %edi,%eax
486b     486b:	f3 0f b8 c7          	popcnt %edi,%eax
486f     486f:	f3 0f b8 c7          	popcnt %edi,%eax
4873     4873:	f3 0f b8 c7          	popcnt %edi,%eax
4877     4877:	f3 0f b8 c7          	popcnt %edi,%eax
487b     487b:	f3 0f b8 c7          	popcnt %edi,%eax
487f     487f:	f3 0f b8 c7          	popcnt %edi,%eax
4883     4883:	f3 0f b8 c7          	popcnt %edi,%eax
4887     4887:	f3 0f b8 c7          	popcnt %edi,%eax
488b     488b:	f3 0f b8 c7          	popcnt %edi,%eax
488f     488f:	f3 0f b8 c7          	popcnt %edi,%eax
4893     4893:	f3 0f b8 c7          	popcnt %edi,%eax
4897     4897:	f3 0f b8 c7          	popcnt %edi,%eax
489b     489b:	f3 0f b8 c7          	popcnt %edi,%eax
489f     489f:	f3 0f b8 c7          	popcnt %edi,%eax
48a3     48a3:	f3 0f b8 c7          	popcnt %edi,%eax
48a7     48a7:	f3 0f b8 c7          	popcnt %edi,%eax
48ab     48ab:	f3 0f b8 c7          	popcnt %edi,%eax
48af     48af:	fb                   	sti
48b0     48b0:	9c                   	pushf
48b1     48b1:	58                   	pop    %rax
48b2     48b2:	fa                   	cli
48b3     48b3:	e8 00 00 00 00       	call   48b8 <.altinstr_replacement+0x48b8>	48b4: R_X86_64_PLT32	clear_page_rep-0x4
48b8     48b8:	e8 00 00 00 00       	call   48bd <.altinstr_replacement+0x48bd>	48b9: R_X86_64_PLT32	clear_page_erms-0x4
48bd     48bd:	0f 01 c1             	vmcall
48c0     48c0:	0f 01 d9             	vmmcall
48c3     48c3:	0f 01 c1             	vmcall
48c6     48c6:	0f 01 d9             	vmmcall
48c9     48c9:	0f 01 c1             	vmcall
48cc     48cc:	0f 01 d9             	vmmcall
48cf     48cf:	0f 01 c1             	vmcall
48d2     48d2:	0f 01 d9             	vmmcall
48d5     48d5:	0f 01 c1             	vmcall
48d8     48d8:	0f 01 d9             	vmmcall
48db     48db:	0f 01 c1             	vmcall
48de     48de:	0f 01 d9             	vmmcall
48e1     48e1:	0f 01 c1             	vmcall
48e4     48e4:	0f 01 d9             	vmmcall
48e7     48e7:	0f 01 c1             	vmcall
48ea     48ea:	0f 01 d9             	vmmcall
48ed     48ed:	0f 01 c1             	vmcall
48f0     48f0:	0f 01 d9             	vmmcall
48f3     48f3:	0f 01 c1             	vmcall
48f6     48f6:	0f 01 d9             	vmmcall
48f9     48f9:	0f 01 c1             	vmcall
48fc     48fc:	0f 01 d9             	vmmcall
48ff     48ff:	0f 01 c1             	vmcall
4902     4902:	0f 01 d9             	vmmcall
4905     4905:	0f 01 c1             	vmcall
4908     4908:	0f 01 d9             	vmmcall
490b     490b:	f3 0f b8 c7          	popcnt %edi,%eax
490f     490f:	f3 0f b8 c7          	popcnt %edi,%eax
4913     4913:	f3 0f b8 c7          	popcnt %edi,%eax
4917     4917:	f3 0f b8 c7          	popcnt %edi,%eax
491b     491b:	f3 0f b8 c7          	popcnt %edi,%eax
491f     491f:	f3 0f b8 c7          	popcnt %edi,%eax
4923     4923:	f3 0f b8 c7          	popcnt %edi,%eax
4927     4927:	f3 0f b8 c7          	popcnt %edi,%eax
492b     492b:	f3 0f b8 c7          	popcnt %edi,%eax
492f     492f:	9c                   	pushf
4930     4930:	58                   	pop    %rax
4931     4931:	9c                   	pushf
4932     4932:	58                   	pop    %rax
4933     4933:	9c                   	pushf
4934     4934:	58                   	pop    %rax
4935     4935:	9c                   	pushf
4936     4936:	58                   	pop    %rax
4937     4937:	9c                   	pushf
4938     4938:	58                   	pop    %rax
4939     4939:	9c                   	pushf
493a     493a:	58                   	pop    %rax
493b     493b:	9c                   	pushf
493c     493c:	58                   	pop    %rax
493d     493d:	9c                   	pushf
493e     493e:	58                   	pop    %rax
493f     493f:	9c                   	pushf
4940     4940:	58                   	pop    %rax
4941     4941:	e8 00 00 00 00       	call   4946 <.altinstr_replacement+0x4946>	4942: R_X86_64_PLT32	clear_page_rep-0x4
4946     4946:	e8 00 00 00 00       	call   494b <.altinstr_replacement+0x494b>	4947: R_X86_64_PLT32	clear_page_erms-0x4
494b     494b:	9c                   	pushf
494c     494c:	58                   	pop    %rax
494d     494d:	9c                   	pushf
494e     494e:	58                   	pop    %rax
494f     494f:	49 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r13
4959     4959:	9c                   	pushf
495a     495a:	58                   	pop    %rax
495b     495b:	fa                   	cli
495c     495c:	fb                   	sti
495d     495d:	f3 0f b8 c7          	popcnt %edi,%eax
4961     4961:	49 be 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r14
496b     496b:	f3 0f b8 c7          	popcnt %edi,%eax
496f     496f:	9c                   	pushf
4970     4970:	58                   	pop    %rax
4971     4971:	fa                   	cli
4972     4972:	9c                   	pushf
4973     4973:	58                   	pop    %rax
4974     4974:	fb                   	sti
4975     4975:	9c                   	pushf
4976     4976:	58                   	pop    %rax
4977     4977:	fa                   	cli
4978     4978:	9c                   	pushf
4979     4979:	58                   	pop    %rax
497a     497a:	fb                   	sti
497b     497b:	9c                   	pushf
497c     497c:	58                   	pop    %rax
497d     497d:	9c                   	pushf
497e     497e:	58                   	pop    %rax
497f     497f:	9c                   	pushf
4980     4980:	58                   	pop    %rax
4981     4981:	9c                   	pushf
4982     4982:	58                   	pop    %rax
4983     4983:	9c                   	pushf
4984     4984:	58                   	pop    %rax
4985     4985:	e9 00 00 00 00       	jmp    498a <.altinstr_replacement+0x498a>	4986: R_X86_64_PC32	.text+0x47c2b04
498a     498a:	e9 00 00 00 00       	jmp    498f <.altinstr_replacement+0x498f>	498b: R_X86_64_PC32	.text+0x47c2afc
498f     498f:	e9 00 00 00 00       	jmp    4994 <.altinstr_replacement+0x4994>	4990: R_X86_64_PC32	.init.text+0x1f0e8b
4994     4994:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4999     4999:	f3 48 0f b8 c7       	popcnt %rdi,%rax
499e     499e:	f3 48 0f b8 c7       	popcnt %rdi,%rax
49a3     49a3:	f3 48 0f b8 c7       	popcnt %rdi,%rax
49a8     49a8:	f3 48 0f b8 c7       	popcnt %rdi,%rax
49ad     49ad:	9c                   	pushf
49ae     49ae:	58                   	pop    %rax
49af     49af:	fa                   	cli
49b0     49b0:	fb                   	sti
49b1     49b1:	9c                   	pushf
49b2     49b2:	58                   	pop    %rax
49b3     49b3:	fa                   	cli
49b4     49b4:	9c                   	pushf
49b5     49b5:	58                   	pop    %rax
49b6     49b6:	fb                   	sti
49b7     49b7:	48 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbp
49c1     49c1:	0f 01 cb             	stac
49c4     49c4:	e8 00 00 00 00       	call   49c9 <.altinstr_replacement+0x49c9>	49c5: R_X86_64_PLT32	clear_user_erms-0x4
49c9     49c9:	e8 00 00 00 00       	call   49ce <.altinstr_replacement+0x49ce>	49ca: R_X86_64_PLT32	clear_user_rep_good-0x4
49ce     49ce:	e8 00 00 00 00       	call   49d3 <.altinstr_replacement+0x49d3>	49cf: R_X86_64_PLT32	clear_user_original-0x4
49d3     49d3:	0f 01 ca             	clac
49d6     49d6:	9c                   	pushf
49d7     49d7:	58                   	pop    %rax
49d8     49d8:	fa                   	cli
49d9     49d9:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
49e3     49e3:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
49ed     49ed:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
49f7     49f7:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
4a01     4a01:	48 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbp
4a0b     4a0b:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
4a15     4a15:	49 be 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r14
4a1f     4a1f:	9c                   	pushf
4a20     4a20:	58                   	pop    %rax
4a21     4a21:	fa                   	cli
4a22     4a22:	9c                   	pushf
4a23     4a23:	58                   	pop    %rax
4a24     4a24:	fb                   	sti
4a25     4a25:	9c                   	pushf
4a26     4a26:	58                   	pop    %rax
4a27     4a27:	fa                   	cli
4a28     4a28:	9c                   	pushf
4a29     4a29:	58                   	pop    %rax
4a2a     4a2a:	fb                   	sti
4a2b     4a2b:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4a30     4a30:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4a35     4a35:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4a3a     4a3a:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4a3f     4a3f:	0f 0d 4d 00          	prefetchw 0x0(%rbp)
4a43     4a43:	0f 0d 0b             	prefetchw (%rbx)
4a46     4a46:	41 0f 0d 0c 16       	prefetchw (%r14,%rdx,1)
4a4b     4a4b:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4a50     4a50:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4a55     4a55:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4a5a     4a5a:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4a5f     4a5f:	e9 00 00 00 00       	jmp    4a64 <.altinstr_replacement+0x4a64>	4a60: R_X86_64_PC32	.text+0x49445de
4a64     4a64:	48 89 f8             	mov    %rdi,%rax
4a67     4a67:	e9 00 00 00 00       	jmp    4a6c <.altinstr_replacement+0x4a6c>	4a68: R_X86_64_PC32	.text+0x49446b0
4a6c     4a6c:	48 89 f8             	mov    %rdi,%rax
4a6f     4a6f:	48 89 f8             	mov    %rdi,%rax
4a72     4a72:	48 89 f8             	mov    %rdi,%rax
4a75     4a75:	48 89 f8             	mov    %rdi,%rax
4a78     4a78:	e9 00 00 00 00       	jmp    4a7d <.altinstr_replacement+0x4a7d>	4a79: R_X86_64_PC32	.text+0x494617e
4a7d     4a7d:	0f 0d 8d 00 80 ff ff 	prefetchw -0x8000(%rbp)
4a84     4a84:	0f 0d 08             	prefetchw (%rax)
4a87     4a87:	41 0f 0d 4d 00       	prefetchw 0x0(%r13)
4a8c     4a8c:	41 0f 0d 4d 00       	prefetchw 0x0(%r13)
4a91     4a91:	e9 00 00 00 00       	jmp    4a96 <.altinstr_replacement+0x4a96>	4a92: R_X86_64_PC32	.text+0x4947ff2
4a96     4a96:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4a9b     4a9b:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4aa0     4aa0:	e9 00 00 00 00       	jmp    4aa5 <.altinstr_replacement+0x4aa5>	4aa1: R_X86_64_PC32	.text+0x494d532
4aa5     4aa5:	e9 00 00 00 00       	jmp    4aaa <.altinstr_replacement+0x4aaa>	4aa6: R_X86_64_PC32	.text+0x49508af
4aaa     4aaa:	e9 00 00 00 00       	jmp    4aaf <.altinstr_replacement+0x4aaf>	4aab: R_X86_64_PC32	.text+0x4950a72
4aaf     4aaf:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4ab4     4ab4:	f3 0f b8 c7          	popcnt %edi,%eax
4ab8     4ab8:	9c                   	pushf
4ab9     4ab9:	58                   	pop    %rax
4aba     4aba:	fa                   	cli
4abb     4abb:	fb                   	sti
4abc     4abc:	9c                   	pushf
4abd     4abd:	58                   	pop    %rax
4abe     4abe:	fa                   	cli
4abf     4abf:	fb                   	sti
4ac0     4ac0:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4ac5     4ac5:	f3 0f b8 c7          	popcnt %edi,%eax
4ac9     4ac9:	49 bf 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r15
4ad3     4ad3:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
4add     4add:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
4ae7     4ae7:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4aec     4aec:	f3 0f b8 c7          	popcnt %edi,%eax
4af0     4af0:	f3 0f b8 c7          	popcnt %edi,%eax
4af4     4af4:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4af9     4af9:	f3 0f b8 c7          	popcnt %edi,%eax
4afd     4afd:	f3 0f b8 c7          	popcnt %edi,%eax
4b01     4b01:	f3 0f b8 c7          	popcnt %edi,%eax
4b05     4b05:	f3 0f b8 c7          	popcnt %edi,%eax
4b09     4b09:	9c                   	pushf
4b0a     4b0a:	58                   	pop    %rax
4b0b     4b0b:	fa                   	cli
4b0c     4b0c:	9c                   	pushf
4b0d     4b0d:	58                   	pop    %rax
4b0e     4b0e:	fb                   	sti
4b0f     4b0f:	9c                   	pushf
4b10     4b10:	58                   	pop    %rax
4b11     4b11:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4b16     4b16:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4b1b     4b1b:	9c                   	pushf
4b1c     4b1c:	58                   	pop    %rax
4b1d     4b1d:	fa                   	cli
4b1e     4b1e:	9c                   	pushf
4b1f     4b1f:	58                   	pop    %rax
4b20     4b20:	fb                   	sti
4b21     4b21:	9c                   	pushf
4b22     4b22:	58                   	pop    %rax
4b23     4b23:	9c                   	pushf
4b24     4b24:	58                   	pop    %rax
4b25     4b25:	fb                   	sti
4b26     4b26:	9c                   	pushf
4b27     4b27:	58                   	pop    %rax
4b28     4b28:	fa                   	cli
4b29     4b29:	9c                   	pushf
4b2a     4b2a:	58                   	pop    %rax
4b2b     4b2b:	fa                   	cli
4b2c     4b2c:	9c                   	pushf
4b2d     4b2d:	58                   	pop    %rax
4b2e     4b2e:	fb                   	sti
4b2f     4b2f:	9c                   	pushf
4b30     4b30:	58                   	pop    %rax
4b31     4b31:	fa                   	cli
4b32     4b32:	9c                   	pushf
4b33     4b33:	58                   	pop    %rax
4b34     4b34:	fb                   	sti
4b35     4b35:	9c                   	pushf
4b36     4b36:	58                   	pop    %rax
4b37     4b37:	fa                   	cli
4b38     4b38:	9c                   	pushf
4b39     4b39:	58                   	pop    %rax
4b3a     4b3a:	fb                   	sti
4b3b     4b3b:	f3 0f b8 c7          	popcnt %edi,%eax
4b3f     4b3f:	f3 0f b8 c7          	popcnt %edi,%eax
4b43     4b43:	9c                   	pushf
4b44     4b44:	58                   	pop    %rax
4b45     4b45:	fa                   	cli
4b46     4b46:	9c                   	pushf
4b47     4b47:	58                   	pop    %rax
4b48     4b48:	fb                   	sti
4b49     4b49:	9c                   	pushf
4b4a     4b4a:	58                   	pop    %rax
4b4b     4b4b:	fa                   	cli
4b4c     4b4c:	9c                   	pushf
4b4d     4b4d:	58                   	pop    %rax
4b4e     4b4e:	fb                   	sti
4b4f     4b4f:	9c                   	pushf
4b50     4b50:	58                   	pop    %rax
4b51     4b51:	fa                   	cli
4b52     4b52:	9c                   	pushf
4b53     4b53:	58                   	pop    %rax
4b54     4b54:	fb                   	sti
4b55     4b55:	9c                   	pushf
4b56     4b56:	58                   	pop    %rax
4b57     4b57:	fb                   	sti
4b58     4b58:	9c                   	pushf
4b59     4b59:	58                   	pop    %rax
4b5a     4b5a:	9c                   	pushf
4b5b     4b5b:	58                   	pop    %rax
4b5c     4b5c:	fa                   	cli
4b5d     4b5d:	9c                   	pushf
4b5e     4b5e:	58                   	pop    %rax
4b5f     4b5f:	fb                   	sti
4b60     4b60:	9c                   	pushf
4b61     4b61:	58                   	pop    %rax
4b62     4b62:	fa                   	cli
4b63     4b63:	9c                   	pushf
4b64     4b64:	58                   	pop    %rax
4b65     4b65:	fb                   	sti
4b66     4b66:	f3 0f b8 c7          	popcnt %edi,%eax
4b6a     4b6a:	9c                   	pushf
4b6b     4b6b:	58                   	pop    %rax
4b6c     4b6c:	fa                   	cli
4b6d     4b6d:	9c                   	pushf
4b6e     4b6e:	58                   	pop    %rax
4b6f     4b6f:	fb                   	sti
4b70     4b70:	9c                   	pushf
4b71     4b71:	58                   	pop    %rax
4b72     4b72:	fa                   	cli
4b73     4b73:	9c                   	pushf
4b74     4b74:	58                   	pop    %rax
4b75     4b75:	fb                   	sti
4b76     4b76:	9c                   	pushf
4b77     4b77:	58                   	pop    %rax
4b78     4b78:	fa                   	cli
4b79     4b79:	9c                   	pushf
4b7a     4b7a:	58                   	pop    %rax
4b7b     4b7b:	fb                   	sti
4b7c     4b7c:	9c                   	pushf
4b7d     4b7d:	58                   	pop    %rax
4b7e     4b7e:	fa                   	cli
4b7f     4b7f:	9c                   	pushf
4b80     4b80:	58                   	pop    %rax
4b81     4b81:	fb                   	sti
4b82     4b82:	e8 00 00 00 00       	call   4b87 <.altinstr_replacement+0x4b87>	4b83: R_X86_64_PLT32	clear_page_rep-0x4
4b87     4b87:	e8 00 00 00 00       	call   4b8c <.altinstr_replacement+0x4b8c>	4b88: R_X86_64_PLT32	clear_page_erms-0x4
4b8c     4b8c:	e8 00 00 00 00       	call   4b91 <.altinstr_replacement+0x4b91>	4b8d: R_X86_64_PLT32	clear_page_rep-0x4
4b91     4b91:	e8 00 00 00 00       	call   4b96 <.altinstr_replacement+0x4b96>	4b92: R_X86_64_PLT32	clear_page_erms-0x4
4b96     4b96:	e8 00 00 00 00       	call   4b9b <.altinstr_replacement+0x4b9b>	4b97: R_X86_64_PLT32	clear_page_rep-0x4
4b9b     4b9b:	e8 00 00 00 00       	call   4ba0 <.altinstr_replacement+0x4ba0>	4b9c: R_X86_64_PLT32	clear_page_erms-0x4
4ba0     4ba0:	9c                   	pushf
4ba1     4ba1:	58                   	pop    %rax
4ba2     4ba2:	fa                   	cli
4ba3     4ba3:	9c                   	pushf
4ba4     4ba4:	58                   	pop    %rax
4ba5     4ba5:	fb                   	sti
4ba6     4ba6:	f3 0f b8 c7          	popcnt %edi,%eax
4baa     4baa:	9c                   	pushf
4bab     4bab:	58                   	pop    %rax
4bac     4bac:	fa                   	cli
4bad     4bad:	9c                   	pushf
4bae     4bae:	58                   	pop    %rax
4baf     4baf:	fb                   	sti
4bb0     4bb0:	9c                   	pushf
4bb1     4bb1:	58                   	pop    %rax
4bb2     4bb2:	fa                   	cli
4bb3     4bb3:	9c                   	pushf
4bb4     4bb4:	58                   	pop    %rax
4bb5     4bb5:	fb                   	sti
4bb6     4bb6:	9c                   	pushf
4bb7     4bb7:	58                   	pop    %rax
4bb8     4bb8:	fb                   	sti
4bb9     4bb9:	9c                   	pushf
4bba     4bba:	58                   	pop    %rax
4bbb     4bbb:	fa                   	cli
4bbc     4bbc:	9c                   	pushf
4bbd     4bbd:	58                   	pop    %rax
4bbe     4bbe:	fb                   	sti
4bbf     4bbf:	9c                   	pushf
4bc0     4bc0:	58                   	pop    %rax
4bc1     4bc1:	fa                   	cli
4bc2     4bc2:	9c                   	pushf
4bc3     4bc3:	58                   	pop    %rax
4bc4     4bc4:	fb                   	sti
4bc5     4bc5:	9c                   	pushf
4bc6     4bc6:	58                   	pop    %rax
4bc7     4bc7:	fa                   	cli
4bc8     4bc8:	9c                   	pushf
4bc9     4bc9:	58                   	pop    %rax
4bca     4bca:	fb                   	sti
4bcb     4bcb:	9c                   	pushf
4bcc     4bcc:	58                   	pop    %rax
4bcd     4bcd:	f3 0f b8 c7          	popcnt %edi,%eax
4bd1     4bd1:	f3 0f b8 c7          	popcnt %edi,%eax
4bd5     4bd5:	f3 0f b8 c7          	popcnt %edi,%eax
4bd9     4bd9:	f3 0f b8 c7          	popcnt %edi,%eax
4bdd     4bdd:	f3 0f b8 c7          	popcnt %edi,%eax
4be1     4be1:	f3 0f b8 c7          	popcnt %edi,%eax
4be5     4be5:	f3 0f b8 c7          	popcnt %edi,%eax
4be9     4be9:	f3 0f b8 c7          	popcnt %edi,%eax
4bed     4bed:	f3 0f b8 c7          	popcnt %edi,%eax
4bf1     4bf1:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4bf6     4bf6:	f3 0f b8 c7          	popcnt %edi,%eax
4bfa     4bfa:	f3 0f b8 c7          	popcnt %edi,%eax
4bfe     4bfe:	f3 0f b8 c7          	popcnt %edi,%eax
4c02     4c02:	f3 0f b8 c7          	popcnt %edi,%eax
4c06     4c06:	f3 0f b8 c7          	popcnt %edi,%eax
4c0a     4c0a:	f3 0f b8 c7          	popcnt %edi,%eax
4c0e     4c0e:	9c                   	pushf
4c0f     4c0f:	58                   	pop    %rax
4c10     4c10:	fa                   	cli
4c11     4c11:	9c                   	pushf
4c12     4c12:	58                   	pop    %rax
4c13     4c13:	fb                   	sti
4c14     4c14:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4c19     4c19:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4c1e     4c1e:	f3 0f b8 c7          	popcnt %edi,%eax
4c22     4c22:	9c                   	pushf
4c23     4c23:	58                   	pop    %rax
4c24     4c24:	fa                   	cli
4c25     4c25:	9c                   	pushf
4c26     4c26:	58                   	pop    %rax
4c27     4c27:	fb                   	sti
4c28     4c28:	9c                   	pushf
4c29     4c29:	58                   	pop    %rax
4c2a     4c2a:	fa                   	cli
4c2b     4c2b:	9c                   	pushf
4c2c     4c2c:	58                   	pop    %rax
4c2d     4c2d:	fb                   	sti
4c2e     4c2e:	f3 0f b8 c7          	popcnt %edi,%eax
4c32     4c32:	9c                   	pushf
4c33     4c33:	58                   	pop    %rax
4c34     4c34:	9c                   	pushf
4c35     4c35:	58                   	pop    %rax
4c36     4c36:	9c                   	pushf
4c37     4c37:	58                   	pop    %rax
4c38     4c38:	9c                   	pushf
4c39     4c39:	58                   	pop    %rax
4c3a     4c3a:	9c                   	pushf
4c3b     4c3b:	58                   	pop    %rax
4c3c     4c3c:	9c                   	pushf
4c3d     4c3d:	58                   	pop    %rax
4c3e     4c3e:	9c                   	pushf
4c3f     4c3f:	58                   	pop    %rax
4c40     4c40:	9c                   	pushf
4c41     4c41:	58                   	pop    %rax
4c42     4c42:	9c                   	pushf
4c43     4c43:	58                   	pop    %rax
4c44     4c44:	9c                   	pushf
4c45     4c45:	58                   	pop    %rax
4c46     4c46:	9c                   	pushf
4c47     4c47:	58                   	pop    %rax
4c48     4c48:	fa                   	cli
4c49     4c49:	9c                   	pushf
4c4a     4c4a:	58                   	pop    %rax
4c4b     4c4b:	fb                   	sti
4c4c     4c4c:	9c                   	pushf
4c4d     4c4d:	58                   	pop    %rax
4c4e     4c4e:	fa                   	cli
4c4f     4c4f:	fb                   	sti
4c50     4c50:	f3 0f b8 c7          	popcnt %edi,%eax
4c54     4c54:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4c59     4c59:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4c5e     4c5e:	9c                   	pushf
4c5f     4c5f:	58                   	pop    %rax
4c60     4c60:	fa                   	cli
4c61     4c61:	9c                   	pushf
4c62     4c62:	58                   	pop    %rax
4c63     4c63:	fb                   	sti
4c64     4c64:	9c                   	pushf
4c65     4c65:	58                   	pop    %rax
4c66     4c66:	fa                   	cli
4c67     4c67:	9c                   	pushf
4c68     4c68:	58                   	pop    %rax
4c69     4c69:	fb                   	sti
4c6a     4c6a:	9c                   	pushf
4c6b     4c6b:	58                   	pop    %rax
4c6c     4c6c:	fa                   	cli
4c6d     4c6d:	9c                   	pushf
4c6e     4c6e:	58                   	pop    %rax
4c6f     4c6f:	fa                   	cli
4c70     4c70:	9c                   	pushf
4c71     4c71:	58                   	pop    %rax
4c72     4c72:	fb                   	sti
4c73     4c73:	fb                   	sti
4c74     4c74:	0f 0d 8b 18 0e 00 00 	prefetchw 0xe18(%rbx)
4c7b     4c7b:	0f 0d 8b 1c 0e 00 00 	prefetchw 0xe1c(%rbx)
4c82     4c82:	9c                   	pushf
4c83     4c83:	58                   	pop    %rax
4c84     4c84:	fa                   	cli
4c85     4c85:	9c                   	pushf
4c86     4c86:	58                   	pop    %rax
4c87     4c87:	fb                   	sti
4c88     4c88:	9c                   	pushf
4c89     4c89:	58                   	pop    %rax
4c8a     4c8a:	fb                   	sti
4c8b     4c8b:	9c                   	pushf
4c8c     4c8c:	58                   	pop    %rax
4c8d     4c8d:	fb                   	sti
4c8e     4c8e:	9c                   	pushf
4c8f     4c8f:	58                   	pop    %rax
4c90     4c90:	fb                   	sti
4c91     4c91:	9c                   	pushf
4c92     4c92:	58                   	pop    %rax
4c93     4c93:	fb                   	sti
4c94     4c94:	0f 0d 8d 18 0e 00 00 	prefetchw 0xe18(%rbp)
4c9b     4c9b:	0f 0d 8d 1c 0e 00 00 	prefetchw 0xe1c(%rbp)
4ca2     4ca2:	9c                   	pushf
4ca3     4ca3:	58                   	pop    %rax
4ca4     4ca4:	fa                   	cli
4ca5     4ca5:	9c                   	pushf
4ca6     4ca6:	58                   	pop    %rax
4ca7     4ca7:	fb                   	sti
4ca8     4ca8:	41 0f 0d 0c 04       	prefetchw (%r12,%rax,1)
4cad     4cad:	0f 0d 0c 01          	prefetchw (%rcx,%rax,1)
4cb1     4cb1:	41 0f 0d 0c 07       	prefetchw (%r15,%rax,1)
4cb6     4cb6:	9c                   	pushf
4cb7     4cb7:	58                   	pop    %rax
4cb8     4cb8:	fa                   	cli
4cb9     4cb9:	9c                   	pushf
4cba     4cba:	58                   	pop    %rax
4cbb     4cbb:	fb                   	sti
4cbc     4cbc:	0f 0d 08             	prefetchw (%rax)
4cbf     4cbf:	f3 0f b8 c7          	popcnt %edi,%eax
4cc3     4cc3:	f3 0f b8 c7          	popcnt %edi,%eax
4cc7     4cc7:	f3 0f b8 c7          	popcnt %edi,%eax
4ccb     4ccb:	f3 0f b8 c7          	popcnt %edi,%eax
4ccf     4ccf:	f3 0f b8 c7          	popcnt %edi,%eax
4cd3     4cd3:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4cd8     4cd8:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4cdd     4cdd:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4ce2     4ce2:	f3 0f b8 c7          	popcnt %edi,%eax
4ce6     4ce6:	9c                   	pushf
4ce7     4ce7:	58                   	pop    %rax
4ce8     4ce8:	fa                   	cli
4ce9     4ce9:	9c                   	pushf
4cea     4cea:	58                   	pop    %rax
4ceb     4ceb:	fb                   	sti
4cec     4cec:	9c                   	pushf
4ced     4ced:	58                   	pop    %rax
4cee     4cee:	fa                   	cli
4cef     4cef:	9c                   	pushf
4cf0     4cf0:	58                   	pop    %rax
4cf1     4cf1:	fb                   	sti
4cf2     4cf2:	f3 0f b8 c7          	popcnt %edi,%eax
4cf6     4cf6:	9c                   	pushf
4cf7     4cf7:	58                   	pop    %rax
4cf8     4cf8:	fa                   	cli
4cf9     4cf9:	9c                   	pushf
4cfa     4cfa:	58                   	pop    %rax
4cfb     4cfb:	fb                   	sti
4cfc     4cfc:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4d01     4d01:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4d06     4d06:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4d0b     4d0b:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4d10     4d10:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4d15     4d15:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4d1a     4d1a:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4d1f     4d1f:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4d24     4d24:	9c                   	pushf
4d25     4d25:	58                   	pop    %rax
4d26     4d26:	fa                   	cli
4d27     4d27:	9c                   	pushf
4d28     4d28:	58                   	pop    %rax
4d29     4d29:	fb                   	sti
4d2a     4d2a:	9c                   	pushf
4d2b     4d2b:	58                   	pop    %rax
4d2c     4d2c:	fa                   	cli
4d2d     4d2d:	fb                   	sti
4d2e     4d2e:	f3 0f b8 c7          	popcnt %edi,%eax
4d32     4d32:	f3 0f b8 c7          	popcnt %edi,%eax
4d36     4d36:	9c                   	pushf
4d37     4d37:	58                   	pop    %rax
4d38     4d38:	fa                   	cli
4d39     4d39:	9c                   	pushf
4d3a     4d3a:	58                   	pop    %rax
4d3b     4d3b:	fb                   	sti
4d3c     4d3c:	9c                   	pushf
4d3d     4d3d:	58                   	pop    %rax
4d3e     4d3e:	fa                   	cli
4d3f     4d3f:	fb                   	sti
4d40     4d40:	9c                   	pushf
4d41     4d41:	58                   	pop    %rax
4d42     4d42:	fa                   	cli
4d43     4d43:	9c                   	pushf
4d44     4d44:	58                   	pop    %rax
4d45     4d45:	fb                   	sti
4d46     4d46:	0f 0d 08             	prefetchw (%rax)
4d49     4d49:	0f 0d 08             	prefetchw (%rax)
4d4c     4d4c:	0f 0d 08             	prefetchw (%rax)
4d4f     4d4f:	0f 0d 08             	prefetchw (%rax)
4d52     4d52:	0f 0d 0b             	prefetchw (%rbx)
4d55     4d55:	0f 0d 08             	prefetchw (%rax)
4d58     4d58:	0f 0d 08             	prefetchw (%rax)
4d5b     4d5b:	0f 0d 08             	prefetchw (%rax)
4d5e     4d5e:	41 0f 0d 0c 24       	prefetchw (%r12)
4d63     4d63:	0f 0d 08             	prefetchw (%rax)
4d66     4d66:	f3 0f b8 c7          	popcnt %edi,%eax
4d6a     4d6a:	f3 0f b8 c7          	popcnt %edi,%eax
4d6e     4d6e:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4d73     4d73:	0f 0d 88 40 02 00 00 	prefetchw 0x240(%rax)
4d7a     4d7a:	0f 0d 88 e4 00 00 00 	prefetchw 0xe4(%rax)
4d81     4d81:	0f 0d 88 00 02 00 00 	prefetchw 0x200(%rax)
4d88     4d88:	0f 0d 08             	prefetchw (%rax)
4d8b     4d8b:	f3 0f b8 c7          	popcnt %edi,%eax
4d8f     4d8f:	f3 0f b8 c7          	popcnt %edi,%eax
4d93     4d93:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4d98     4d98:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4d9d     4d9d:	9c                   	pushf
4d9e     4d9e:	58                   	pop    %rax
4d9f     4d9f:	fa                   	cli
4da0     4da0:	9c                   	pushf
4da1     4da1:	58                   	pop    %rax
4da2     4da2:	fb                   	sti
4da3     4da3:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4da8     4da8:	0f 0d 88 e4 00 00 00 	prefetchw 0xe4(%rax)
4daf     4daf:	0f 0d 88 40 02 00 00 	prefetchw 0x240(%rax)
4db6     4db6:	0f 0d 88 00 02 00 00 	prefetchw 0x200(%rax)
4dbd     4dbd:	0f 0d 08             	prefetchw (%rax)
4dc0     4dc0:	0f 0d 48 40          	prefetchw 0x40(%rax)
4dc4     4dc4:	9c                   	pushf
4dc5     4dc5:	58                   	pop    %rax
4dc6     4dc6:	fa                   	cli
4dc7     4dc7:	9c                   	pushf
4dc8     4dc8:	58                   	pop    %rax
4dc9     4dc9:	fb                   	sti
4dca     4dca:	9c                   	pushf
4dcb     4dcb:	58                   	pop    %rax
4dcc     4dcc:	fa                   	cli
4dcd     4dcd:	9c                   	pushf
4dce     4dce:	58                   	pop    %rax
4dcf     4dcf:	fb                   	sti
4dd0     4dd0:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4dd5     4dd5:	9c                   	pushf
4dd6     4dd6:	58                   	pop    %rax
4dd7     4dd7:	fa                   	cli
4dd8     4dd8:	9c                   	pushf
4dd9     4dd9:	58                   	pop    %rax
4dda     4dda:	fb                   	sti
4ddb     4ddb:	0f 0d 4d 20          	prefetchw 0x20(%rbp)
4ddf     4ddf:	0f 0d 4d 60          	prefetchw 0x60(%rbp)
4de3     4de3:	9c                   	pushf
4de4     4de4:	58                   	pop    %rax
4de5     4de5:	fa                   	cli
4de6     4de6:	9c                   	pushf
4de7     4de7:	58                   	pop    %rax
4de8     4de8:	fb                   	sti
4de9     4de9:	0f 0d 08             	prefetchw (%rax)
4dec     4dec:	0f 0d 48 40          	prefetchw 0x40(%rax)
4df0     4df0:	0f 0d 08             	prefetchw (%rax)
4df3     4df3:	0f 0d 48 40          	prefetchw 0x40(%rax)
4df7     4df7:	41 0f 0d 4d 00       	prefetchw 0x0(%r13)
4dfc     4dfc:	41 0f 0d 4d 40       	prefetchw 0x40(%r13)
4e01     4e01:	0f 0d 4d 00          	prefetchw 0x0(%rbp)
4e05     4e05:	0f 0d 4d 40          	prefetchw 0x40(%rbp)
4e09     4e09:	41 0f 0d 08          	prefetchw (%r8)
4e0d     4e0d:	0f 0d 08             	prefetchw (%rax)
4e10     4e10:	41 0f 0d 4d 00       	prefetchw 0x0(%r13)
4e15     4e15:	41 0f 0d 4d 40       	prefetchw 0x40(%r13)
4e1a     4e1a:	0f 0d 4d 00          	prefetchw 0x0(%rbp)
4e1e     4e1e:	0f 0d 4d 40          	prefetchw 0x40(%rbp)
4e22     4e22:	41 0f 0d 4f 20       	prefetchw 0x20(%r15)
4e27     4e27:	41 0f 0d 4f 60       	prefetchw 0x60(%r15)
4e2c     4e2c:	f3 0f b8 c7          	popcnt %edi,%eax
4e30     4e30:	0f 0d 08             	prefetchw (%rax)
4e33     4e33:	0f 0d 48 40          	prefetchw 0x40(%rax)
4e37     4e37:	9c                   	pushf
4e38     4e38:	58                   	pop    %rax
4e39     4e39:	fa                   	cli
4e3a     4e3a:	9c                   	pushf
4e3b     4e3b:	58                   	pop    %rax
4e3c     4e3c:	fb                   	sti
4e3d     4e3d:	9c                   	pushf
4e3e     4e3e:	58                   	pop    %rax
4e3f     4e3f:	fa                   	cli
4e40     4e40:	9c                   	pushf
4e41     4e41:	58                   	pop    %rax
4e42     4e42:	fb                   	sti
4e43     4e43:	9c                   	pushf
4e44     4e44:	58                   	pop    %rax
4e45     4e45:	fa                   	cli
4e46     4e46:	9c                   	pushf
4e47     4e47:	58                   	pop    %rax
4e48     4e48:	fb                   	sti
4e49     4e49:	9c                   	pushf
4e4a     4e4a:	58                   	pop    %rax
4e4b     4e4b:	fa                   	cli
4e4c     4e4c:	9c                   	pushf
4e4d     4e4d:	58                   	pop    %rax
4e4e     4e4e:	fb                   	sti
4e4f     4e4f:	9c                   	pushf
4e50     4e50:	58                   	pop    %rax
4e51     4e51:	fa                   	cli
4e52     4e52:	9c                   	pushf
4e53     4e53:	58                   	pop    %rax
4e54     4e54:	fb                   	sti
4e55     4e55:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4e5a     4e5a:	0f 0d 0b             	prefetchw (%rbx)
4e5d     4e5d:	9c                   	pushf
4e5e     4e5e:	58                   	pop    %rax
4e5f     4e5f:	fa                   	cli
4e60     4e60:	9c                   	pushf
4e61     4e61:	58                   	pop    %rax
4e62     4e62:	fb                   	sti
4e63     4e63:	9c                   	pushf
4e64     4e64:	58                   	pop    %rax
4e65     4e65:	fa                   	cli
4e66     4e66:	9c                   	pushf
4e67     4e67:	58                   	pop    %rax
4e68     4e68:	fb                   	sti
4e69     4e69:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4e6e     4e6e:	41 0f 0d 0c c4       	prefetchw (%r12,%rax,8)
4e73     4e73:	f3 0f b8 c7          	popcnt %edi,%eax
4e77     4e77:	f3 0f b8 c7          	popcnt %edi,%eax
4e7b     4e7b:	f3 0f b8 c7          	popcnt %edi,%eax
4e7f     4e7f:	41 0f 0d 0c c4       	prefetchw (%r12,%rax,8)
4e84     4e84:	f3 0f b8 c7          	popcnt %edi,%eax
4e88     4e88:	f3 0f b8 c7          	popcnt %edi,%eax
4e8c     4e8c:	9c                   	pushf
4e8d     4e8d:	58                   	pop    %rax
4e8e     4e8e:	fa                   	cli
4e8f     4e8f:	9c                   	pushf
4e90     4e90:	58                   	pop    %rax
4e91     4e91:	fb                   	sti
4e92     4e92:	0f 0d 08             	prefetchw (%rax)
4e95     4e95:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4e9a     4e9a:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4e9f     4e9f:	9c                   	pushf
4ea0     4ea0:	58                   	pop    %rax
4ea1     4ea1:	fa                   	cli
4ea2     4ea2:	0f 0d 08             	prefetchw (%rax)
4ea5     4ea5:	fb                   	sti
4ea6     4ea6:	9c                   	pushf
4ea7     4ea7:	58                   	pop    %rax
4ea8     4ea8:	fa                   	cli
4ea9     4ea9:	fb                   	sti
4eaa     4eaa:	fb                   	sti
4eab     4eab:	9c                   	pushf
4eac     4eac:	58                   	pop    %rax
4ead     4ead:	fa                   	cli
4eae     4eae:	fb                   	sti
4eaf     4eaf:	9c                   	pushf
4eb0     4eb0:	58                   	pop    %rax
4eb1     4eb1:	fa                   	cli
4eb2     4eb2:	fb                   	sti
4eb3     4eb3:	9c                   	pushf
4eb4     4eb4:	58                   	pop    %rax
4eb5     4eb5:	fa                   	cli
4eb6     4eb6:	9c                   	pushf
4eb7     4eb7:	58                   	pop    %rax
4eb8     4eb8:	fb                   	sti
4eb9     4eb9:	9c                   	pushf
4eba     4eba:	58                   	pop    %rax
4ebb     4ebb:	fa                   	cli
4ebc     4ebc:	9c                   	pushf
4ebd     4ebd:	58                   	pop    %rax
4ebe     4ebe:	fb                   	sti
4ebf     4ebf:	f3 0f b8 c7          	popcnt %edi,%eax
4ec3     4ec3:	f3 0f b8 c7          	popcnt %edi,%eax
4ec7     4ec7:	f3 0f b8 c7          	popcnt %edi,%eax
4ecb     4ecb:	f3 0f b8 c7          	popcnt %edi,%eax
4ecf     4ecf:	f3 0f b8 c7          	popcnt %edi,%eax
4ed3     4ed3:	f3 0f b8 c7          	popcnt %edi,%eax
4ed7     4ed7:	f3 0f b8 c7          	popcnt %edi,%eax
4edb     4edb:	f3 0f b8 c7          	popcnt %edi,%eax
4edf     4edf:	9c                   	pushf
4ee0     4ee0:	58                   	pop    %rax
4ee1     4ee1:	fa                   	cli
4ee2     4ee2:	9c                   	pushf
4ee3     4ee3:	58                   	pop    %rax
4ee4     4ee4:	fb                   	sti
4ee5     4ee5:	f3 0f b8 c7          	popcnt %edi,%eax
4ee9     4ee9:	f3 0f b8 c7          	popcnt %edi,%eax
4eed     4eed:	f3 0f b8 c7          	popcnt %edi,%eax
4ef1     4ef1:	f3 0f b8 c7          	popcnt %edi,%eax
4ef5     4ef5:	f3 0f b8 c7          	popcnt %edi,%eax
4ef9     4ef9:	f3 0f b8 c7          	popcnt %edi,%eax
4efd     4efd:	f3 0f b8 c7          	popcnt %edi,%eax
4f01     4f01:	f3 0f b8 c7          	popcnt %edi,%eax
4f05     4f05:	9c                   	pushf
4f06     4f06:	58                   	pop    %rax
4f07     4f07:	fa                   	cli
4f08     4f08:	9c                   	pushf
4f09     4f09:	58                   	pop    %rax
4f0a     4f0a:	fb                   	sti
4f0b     4f0b:	f3 0f b8 c7          	popcnt %edi,%eax
4f0f     4f0f:	9c                   	pushf
4f10     4f10:	58                   	pop    %rax
4f11     4f11:	9c                   	pushf
4f12     4f12:	58                   	pop    %rax
4f13     4f13:	9c                   	pushf
4f14     4f14:	58                   	pop    %rax
4f15     4f15:	fa                   	cli
4f16     4f16:	9c                   	pushf
4f17     4f17:	58                   	pop    %rax
4f18     4f18:	fb                   	sti
4f19     4f19:	9c                   	pushf
4f1a     4f1a:	58                   	pop    %rax
4f1b     4f1b:	fa                   	cli
4f1c     4f1c:	9c                   	pushf
4f1d     4f1d:	58                   	pop    %rax
4f1e     4f1e:	fb                   	sti
4f1f     4f1f:	9c                   	pushf
4f20     4f20:	58                   	pop    %rax
4f21     4f21:	f3 0f b8 c7          	popcnt %edi,%eax
4f25     4f25:	f3 0f b8 c7          	popcnt %edi,%eax
4f29     4f29:	f3 0f b8 c7          	popcnt %edi,%eax
4f2d     4f2d:	f3 0f b8 c7          	popcnt %edi,%eax
4f31     4f31:	f3 0f b8 c7          	popcnt %edi,%eax
4f35     4f35:	f3 0f b8 c7          	popcnt %edi,%eax
4f39     4f39:	f3 0f b8 c7          	popcnt %edi,%eax
4f3d     4f3d:	f3 0f b8 c7          	popcnt %edi,%eax
4f41     4f41:	f3 0f b8 c7          	popcnt %edi,%eax
4f45     4f45:	f3 0f b8 c7          	popcnt %edi,%eax
4f49     4f49:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4f4e     4f4e:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4f53     4f53:	f3 0f b8 c7          	popcnt %edi,%eax
4f57     4f57:	f3 0f b8 c7          	popcnt %edi,%eax
4f5b     4f5b:	f3 0f b8 c7          	popcnt %edi,%eax
4f5f     4f5f:	f3 0f b8 c7          	popcnt %edi,%eax
4f63     4f63:	f3 48 0f b8 c7       	popcnt %rdi,%rax
4f68     4f68:	f3 0f b8 c7          	popcnt %edi,%eax
4f6c     4f6c:	f3 0f b8 c7          	popcnt %edi,%eax
4f70     4f70:	f3 0f b8 c7          	popcnt %edi,%eax
4f74     4f74:	f3 0f b8 c7          	popcnt %edi,%eax
4f78     4f78:	f3 0f b8 c7          	popcnt %edi,%eax
4f7c     4f7c:	f3 0f b8 c7          	popcnt %edi,%eax
4f80     4f80:	f3 0f b8 c7          	popcnt %edi,%eax
4f84     4f84:	f3 0f b8 c7          	popcnt %edi,%eax
4f88     4f88:	f3 0f b8 c7          	popcnt %edi,%eax
4f8c     4f8c:	f3 0f b8 c7          	popcnt %edi,%eax
4f90     4f90:	f3 0f b8 c7          	popcnt %edi,%eax
4f94     4f94:	f3 0f b8 c7          	popcnt %edi,%eax
4f98     4f98:	f3 0f b8 c7          	popcnt %edi,%eax
4f9c     4f9c:	f3 0f b8 c7          	popcnt %edi,%eax
4fa0     4fa0:	f3 0f b8 c7          	popcnt %edi,%eax
4fa4     4fa4:	f3 0f b8 c7          	popcnt %edi,%eax
4fa8     4fa8:	f3 0f b8 c7          	popcnt %edi,%eax
4fac     4fac:	f3 0f b8 c7          	popcnt %edi,%eax
4fb0     4fb0:	f3 0f b8 c7          	popcnt %edi,%eax
4fb4     4fb4:	f3 0f b8 c7          	popcnt %edi,%eax
4fb8     4fb8:	f3 0f b8 c7          	popcnt %edi,%eax
4fbc     4fbc:	f3 0f b8 c7          	popcnt %edi,%eax
4fc0     4fc0:	f3 0f b8 c7          	popcnt %edi,%eax
4fc4     4fc4:	f3 0f b8 c7          	popcnt %edi,%eax
4fc8     4fc8:	f3 0f b8 c7          	popcnt %edi,%eax
4fcc     4fcc:	f3 0f b8 c7          	popcnt %edi,%eax
4fd0     4fd0:	f3 0f b8 c7          	popcnt %edi,%eax
4fd4     4fd4:	f3 0f b8 c7          	popcnt %edi,%eax
4fd8     4fd8:	f3 0f b8 c7          	popcnt %edi,%eax
4fdc     4fdc:	f3 0f b8 c7          	popcnt %edi,%eax
4fe0     4fe0:	f3 0f b8 c7          	popcnt %edi,%eax
4fe4     4fe4:	f3 0f b8 c7          	popcnt %edi,%eax
4fe8     4fe8:	f3 0f b8 c7          	popcnt %edi,%eax
4fec     4fec:	f3 0f b8 c7          	popcnt %edi,%eax
4ff0     4ff0:	f3 0f b8 c7          	popcnt %edi,%eax
4ff4     4ff4:	f3 0f b8 c7          	popcnt %edi,%eax
4ff8     4ff8:	f3 0f b8 c7          	popcnt %edi,%eax
4ffc     4ffc:	f3 0f b8 c7          	popcnt %edi,%eax
5000     5000:	f3 0f b8 c7          	popcnt %edi,%eax
5004     5004:	f3 0f b8 c7          	popcnt %edi,%eax
5008     5008:	f3 0f b8 c7          	popcnt %edi,%eax
500c     500c:	f3 0f b8 c7          	popcnt %edi,%eax
5010     5010:	f3 0f b8 c7          	popcnt %edi,%eax
5014     5014:	f3 0f b8 c7          	popcnt %edi,%eax
5018     5018:	f3 0f b8 c7          	popcnt %edi,%eax
501c     501c:	f3 0f b8 c7          	popcnt %edi,%eax
5020     5020:	f3 0f b8 c7          	popcnt %edi,%eax
5024     5024:	f3 0f b8 c7          	popcnt %edi,%eax
5028     5028:	f3 0f b8 c7          	popcnt %edi,%eax
502c     502c:	f3 0f b8 c7          	popcnt %edi,%eax
5030     5030:	f3 0f b8 c7          	popcnt %edi,%eax
5034     5034:	f3 0f b8 c7          	popcnt %edi,%eax
5038     5038:	f3 0f b8 c7          	popcnt %edi,%eax
503c     503c:	f3 0f b8 c7          	popcnt %edi,%eax
5040     5040:	f3 0f b8 c7          	popcnt %edi,%eax
5044     5044:	9c                   	pushf
5045     5045:	58                   	pop    %rax
5046     5046:	9c                   	pushf
5047     5047:	58                   	pop    %rax
5048     5048:	9c                   	pushf
5049     5049:	58                   	pop    %rax
504a     504a:	fb                   	sti
504b     504b:	9c                   	pushf
504c     504c:	58                   	pop    %rax
504d     504d:	fb                   	sti
504e     504e:	9c                   	pushf
504f     504f:	58                   	pop    %rax
5050     5050:	fb                   	sti
5051     5051:	9c                   	pushf
5052     5052:	58                   	pop    %rax
5053     5053:	fa                   	cli
5054     5054:	9c                   	pushf
5055     5055:	58                   	pop    %rax
5056     5056:	fb                   	sti
5057     5057:	9c                   	pushf
5058     5058:	58                   	pop    %rax
5059     5059:	fb                   	sti
505a     505a:	9c                   	pushf
505b     505b:	58                   	pop    %rax
505c     505c:	fb                   	sti
505d     505d:	9c                   	pushf
505e     505e:	58                   	pop    %rax
505f     505f:	fb                   	sti
5060     5060:	9c                   	pushf
5061     5061:	58                   	pop    %rax
5062     5062:	fb                   	sti
5063     5063:	9c                   	pushf
5064     5064:	58                   	pop    %rax
5065     5065:	fb                   	sti
5066     5066:	9c                   	pushf
5067     5067:	58                   	pop    %rax
5068     5068:	fb                   	sti
5069     5069:	9c                   	pushf
506a     506a:	58                   	pop    %rax
506b     506b:	fb                   	sti
506c     506c:	9c                   	pushf
506d     506d:	58                   	pop    %rax
506e     506e:	fb                   	sti
506f     506f:	f3 0f b8 c7          	popcnt %edi,%eax
5073     5073:	f3 0f b8 c7          	popcnt %edi,%eax
5077     5077:	f3 0f b8 c7          	popcnt %edi,%eax
507b     507b:	f3 0f b8 c7          	popcnt %edi,%eax
507f     507f:	f3 48 0f b8 c7       	popcnt %rdi,%rax
5084     5084:	f3 0f b8 c7          	popcnt %edi,%eax
5088     5088:	f3 0f b8 c7          	popcnt %edi,%eax
508c     508c:	9c                   	pushf
508d     508d:	58                   	pop    %rax
508e     508e:	fa                   	cli
508f     508f:	9c                   	pushf
5090     5090:	58                   	pop    %rax
5091     5091:	fb                   	sti
5092     5092:	9c                   	pushf
5093     5093:	58                   	pop    %rax
5094     5094:	fa                   	cli
5095     5095:	9c                   	pushf
5096     5096:	58                   	pop    %rax
5097     5097:	fb                   	sti
5098     5098:	9c                   	pushf
5099     5099:	58                   	pop    %rax
509a     509a:	9c                   	pushf
509b     509b:	58                   	pop    %rax
509c     509c:	9c                   	pushf
509d     509d:	58                   	pop    %rax
509e     509e:	f3 0f b8 c7          	popcnt %edi,%eax
50a2     50a2:	9c                   	pushf
50a3     50a3:	58                   	pop    %rax
50a4     50a4:	fa                   	cli
50a5     50a5:	9c                   	pushf
50a6     50a6:	58                   	pop    %rax
50a7     50a7:	fb                   	sti
50a8     50a8:	f3 48 0f b8 c7       	popcnt %rdi,%rax
50ad     50ad:	9c                   	pushf
50ae     50ae:	58                   	pop    %rax
50af     50af:	fa                   	cli
50b0     50b0:	9c                   	pushf
50b1     50b1:	58                   	pop    %rax
50b2     50b2:	fb                   	sti
50b3     50b3:	9c                   	pushf
50b4     50b4:	58                   	pop    %rax
50b5     50b5:	9c                   	pushf
50b6     50b6:	58                   	pop    %rax
50b7     50b7:	9c                   	pushf
50b8     50b8:	58                   	pop    %rax
50b9     50b9:	fa                   	cli
50ba     50ba:	fb                   	sti
50bb     50bb:	9c                   	pushf
50bc     50bc:	58                   	pop    %rax
50bd     50bd:	fa                   	cli
50be     50be:	9c                   	pushf
50bf     50bf:	58                   	pop    %rax
50c0     50c0:	fb                   	sti
50c1     50c1:	9c                   	pushf
50c2     50c2:	58                   	pop    %rax
50c3     50c3:	fa                   	cli
50c4     50c4:	9c                   	pushf
50c5     50c5:	58                   	pop    %rax
50c6     50c6:	fb                   	sti
50c7     50c7:	9c                   	pushf
50c8     50c8:	58                   	pop    %rax
50c9     50c9:	fa                   	cli
50ca     50ca:	fb                   	sti
50cb     50cb:	f3 0f b8 c7          	popcnt %edi,%eax
50cf     50cf:	f3 0f b8 c7          	popcnt %edi,%eax
50d3     50d3:	e9 00 00 00 00       	jmp    50d8 <.altinstr_replacement+0x50d8>	50d4: R_X86_64_PC32	.text+0x801499c
50d8     50d8:	e9 00 00 00 00       	jmp    50dd <.altinstr_replacement+0x50dd>	50d9: R_X86_64_PC32	.text+0x8014885
50dd     50dd:	48 89 f8             	mov    %rdi,%rax
50e0     50e0:	49 be 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r14
50ea     50ea:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
50f4     50f4:	f3 0f b8 c7          	popcnt %edi,%eax
50f8     50f8:	9c                   	pushf
50f9     50f9:	58                   	pop    %rax
50fa     50fa:	fa                   	cli
50fb     50fb:	fb                   	sti
50fc     50fc:	49 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r13
5106     5106:	9c                   	pushf
5107     5107:	58                   	pop    %rax
5108     5108:	fa                   	cli
5109     5109:	fb                   	sti
510a     510a:	9c                   	pushf
510b     510b:	58                   	pop    %rax
510c     510c:	fa                   	cli
510d     510d:	9c                   	pushf
510e     510e:	58                   	pop    %rax
510f     510f:	fb                   	sti
5110     5110:	9c                   	pushf
5111     5111:	58                   	pop    %rax
5112     5112:	fa                   	cli
5113     5113:	9c                   	pushf
5114     5114:	58                   	pop    %rax
5115     5115:	fb                   	sti
5116     5116:	f3 0f b8 c7          	popcnt %edi,%eax
511a     511a:	f3 0f b8 c7          	popcnt %edi,%eax
511e     511e:	f3 0f b8 c7          	popcnt %edi,%eax
5122     5122:	f3 0f b8 c7          	popcnt %edi,%eax
5126     5126:	0f 0d 08             	prefetchw (%rax)
5129     5129:	9c                   	pushf
512a     512a:	58                   	pop    %rax
512b     512b:	fa                   	cli
512c     512c:	9c                   	pushf
512d     512d:	58                   	pop    %rax
512e     512e:	fb                   	sti
512f     512f:	9c                   	pushf
5130     5130:	58                   	pop    %rax
5131     5131:	9c                   	pushf
5132     5132:	58                   	pop    %rax
5133     5133:	fa                   	cli
5134     5134:	9c                   	pushf
5135     5135:	58                   	pop    %rax
5136     5136:	fb                   	sti
5137     5137:	9c                   	pushf
5138     5138:	58                   	pop    %rax
5139     5139:	fa                   	cli
513a     513a:	9c                   	pushf
513b     513b:	58                   	pop    %rax
513c     513c:	fb                   	sti
513d     513d:	9c                   	pushf
513e     513e:	58                   	pop    %rax
513f     513f:	fa                   	cli
5140     5140:	9c                   	pushf
5141     5141:	58                   	pop    %rax
5142     5142:	fb                   	sti
5143     5143:	0f 0d 0b             	prefetchw (%rbx)
5146     5146:	0f 0d 08             	prefetchw (%rax)
5149     5149:	9c                   	pushf
514a     514a:	58                   	pop    %rax
514b     514b:	fa                   	cli
514c     514c:	9c                   	pushf
514d     514d:	58                   	pop    %rax
514e     514e:	fb                   	sti
514f     514f:	0f 0d 0b             	prefetchw (%rbx)
5152     5152:	9c                   	pushf
5153     5153:	58                   	pop    %rax
5154     5154:	fa                   	cli
5155     5155:	9c                   	pushf
5156     5156:	58                   	pop    %rax
5157     5157:	fb                   	sti
5158     5158:	41 0f 0d 4d 00       	prefetchw 0x0(%r13)
515d     515d:	41 0f 0d 0e          	prefetchw (%r14)
5161     5161:	41 0f 0d 4d 00       	prefetchw 0x0(%r13)
5166     5166:	9c                   	pushf
5167     5167:	58                   	pop    %rax
5168     5168:	fa                   	cli
5169     5169:	fb                   	sti
516a     516a:	9c                   	pushf
516b     516b:	58                   	pop    %rax
516c     516c:	fa                   	cli
516d     516d:	fb                   	sti
516e     516e:	f3 0f b8 c7          	popcnt %edi,%eax
5172     5172:	f3 0f b8 c7          	popcnt %edi,%eax
5176     5176:	f3 0f b8 c7          	popcnt %edi,%eax
517a     517a:	9c                   	pushf
517b     517b:	58                   	pop    %rax
517c     517c:	fa                   	cli
517d     517d:	9c                   	pushf
517e     517e:	58                   	pop    %rax
517f     517f:	fb                   	sti
5180     5180:	9c                   	pushf
5181     5181:	58                   	pop    %rax
5182     5182:	fa                   	cli
5183     5183:	9c                   	pushf
5184     5184:	58                   	pop    %rax
5185     5185:	fb                   	sti
5186     5186:	f3 48 0f b8 c7       	popcnt %rdi,%rax
518b     518b:	49 be 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r14
5195     5195:	0f 01 cb             	stac
5198     5198:	e8 00 00 00 00       	call   519d <.altinstr_replacement+0x519d>	5199: R_X86_64_PLT32	clear_user_erms-0x4
519d     519d:	e8 00 00 00 00       	call   51a2 <.altinstr_replacement+0x51a2>	519e: R_X86_64_PLT32	clear_user_rep_good-0x4
51a2     51a2:	e8 00 00 00 00       	call   51a7 <.altinstr_replacement+0x51a7>	51a3: R_X86_64_PLT32	clear_user_original-0x4
51a7     51a7:	0f 01 ca             	clac
51aa     51aa:	f3 0f b8 c7          	popcnt %edi,%eax
51ae     51ae:	f3 0f b8 c7          	popcnt %edi,%eax
51b2     51b2:	0f 01 c1             	vmcall
51b5     51b5:	0f 01 d9             	vmmcall
51b8     51b8:	0f 01 c1             	vmcall
51bb     51bb:	0f 01 d9             	vmmcall
51be     51be:	0f 01 c1             	vmcall
51c1     51c1:	0f 01 d9             	vmmcall
51c4     51c4:	0f 01 c1             	vmcall
51c7     51c7:	0f 01 d9             	vmmcall
51ca     51ca:	0f 01 c1             	vmcall
51cd     51cd:	0f 01 d9             	vmmcall
51d0     51d0:	0f 01 c1             	vmcall
51d3     51d3:	0f 01 d9             	vmmcall
51d6     51d6:	0f 01 c1             	vmcall
51d9     51d9:	0f 01 d9             	vmmcall
51dc     51dc:	0f 01 c1             	vmcall
51df     51df:	0f 01 d9             	vmmcall
51e2     51e2:	0f 01 c1             	vmcall
51e5     51e5:	0f 01 d9             	vmmcall
51e8     51e8:	0f 01 c1             	vmcall
51eb     51eb:	0f 01 d9             	vmmcall
51ee     51ee:	9c                   	pushf
51ef     51ef:	58                   	pop    %rax
51f0     51f0:	fa                   	cli
51f1     51f1:	9c                   	pushf
51f2     51f2:	58                   	pop    %rax
51f3     51f3:	fb                   	sti
51f4     51f4:	9c                   	pushf
51f5     51f5:	58                   	pop    %rax
51f6     51f6:	fa                   	cli
51f7     51f7:	9c                   	pushf
51f8     51f8:	58                   	pop    %rax
51f9     51f9:	fb                   	sti
51fa     51fa:	9c                   	pushf
51fb     51fb:	58                   	pop    %rax
51fc     51fc:	fa                   	cli
51fd     51fd:	9c                   	pushf
51fe     51fe:	58                   	pop    %rax
51ff     51ff:	9c                   	pushf
5200     5200:	58                   	pop    %rax
5201     5201:	fa                   	cli
5202     5202:	9c                   	pushf
5203     5203:	58                   	pop    %rax
5204     5204:	fb                   	sti
5205     5205:	fb                   	sti
5206     5206:	9c                   	pushf
5207     5207:	58                   	pop    %rax
5208     5208:	fa                   	cli
5209     5209:	9c                   	pushf
520a     520a:	58                   	pop    %rax
520b     520b:	fb                   	sti
520c     520c:	f3 0f b8 c7          	popcnt %edi,%eax
5210     5210:	f3 0f b8 c7          	popcnt %edi,%eax
5214     5214:	f3 0f b8 c7          	popcnt %edi,%eax
5218     5218:	f3 0f b8 c7          	popcnt %edi,%eax
521c     521c:	9c                   	pushf
521d     521d:	58                   	pop    %rax
521e     521e:	fa                   	cli
521f     521f:	9c                   	pushf
5220     5220:	58                   	pop    %rax
5221     5221:	fb                   	sti
5222     5222:	9c                   	pushf
5223     5223:	58                   	pop    %rax
5224     5224:	fa                   	cli
5225     5225:	9c                   	pushf
5226     5226:	58                   	pop    %rax
5227     5227:	fb                   	sti
5228     5228:	9c                   	pushf
5229     5229:	58                   	pop    %rax
522a     522a:	fa                   	cli
522b     522b:	9c                   	pushf
522c     522c:	58                   	pop    %rax
522d     522d:	fb                   	sti
522e     522e:	9c                   	pushf
522f     522f:	58                   	pop    %rax
5230     5230:	fa                   	cli
5231     5231:	9c                   	pushf
5232     5232:	58                   	pop    %rax
5233     5233:	fb                   	sti
5234     5234:	9c                   	pushf
5235     5235:	58                   	pop    %rax
5236     5236:	fa                   	cli
5237     5237:	9c                   	pushf
5238     5238:	58                   	pop    %rax
5239     5239:	fb                   	sti
523a     523a:	9c                   	pushf
523b     523b:	58                   	pop    %rax
523c     523c:	fa                   	cli
523d     523d:	9c                   	pushf
523e     523e:	58                   	pop    %rax
523f     523f:	fb                   	sti
5240     5240:	9c                   	pushf
5241     5241:	58                   	pop    %rax
5242     5242:	fa                   	cli
5243     5243:	9c                   	pushf
5244     5244:	58                   	pop    %rax
5245     5245:	fb                   	sti
5246     5246:	9c                   	pushf
5247     5247:	58                   	pop    %rax
5248     5248:	fa                   	cli
5249     5249:	9c                   	pushf
524a     524a:	58                   	pop    %rax
524b     524b:	fb                   	sti
524c     524c:	9c                   	pushf
524d     524d:	58                   	pop    %rax
524e     524e:	fa                   	cli
524f     524f:	9c                   	pushf
5250     5250:	58                   	pop    %rax
5251     5251:	fb                   	sti
5252     5252:	9c                   	pushf
5253     5253:	58                   	pop    %rax
5254     5254:	fa                   	cli
5255     5255:	9c                   	pushf
5256     5256:	58                   	pop    %rax
5257     5257:	fb                   	sti
5258     5258:	9c                   	pushf
5259     5259:	58                   	pop    %rax
525a     525a:	fa                   	cli
525b     525b:	9c                   	pushf
525c     525c:	58                   	pop    %rax
525d     525d:	fb                   	sti
525e     525e:	9c                   	pushf
525f     525f:	58                   	pop    %rax
5260     5260:	fa                   	cli
5261     5261:	9c                   	pushf
5262     5262:	58                   	pop    %rax
5263     5263:	fb                   	sti
5264     5264:	9c                   	pushf
5265     5265:	58                   	pop    %rax
5266     5266:	fa                   	cli
5267     5267:	9c                   	pushf
5268     5268:	58                   	pop    %rax
5269     5269:	fb                   	sti
526a     526a:	9c                   	pushf
526b     526b:	58                   	pop    %rax
526c     526c:	fa                   	cli
526d     526d:	9c                   	pushf
526e     526e:	58                   	pop    %rax
526f     526f:	fb                   	sti
5270     5270:	9c                   	pushf
5271     5271:	58                   	pop    %rax
5272     5272:	fa                   	cli
5273     5273:	9c                   	pushf
5274     5274:	58                   	pop    %rax
5275     5275:	fb                   	sti
5276     5276:	f3 0f b8 c7          	popcnt %edi,%eax
527a     527a:	f3 0f b8 c7          	popcnt %edi,%eax
527e     527e:	f3 0f b8 c7          	popcnt %edi,%eax
5282     5282:	f3 0f b8 c7          	popcnt %edi,%eax
5286     5286:	9c                   	pushf
5287     5287:	58                   	pop    %rax
5288     5288:	fa                   	cli
5289     5289:	fb                   	sti
528a     528a:	9c                   	pushf
528b     528b:	58                   	pop    %rax
528c     528c:	9c                   	pushf
528d     528d:	58                   	pop    %rax
528e     528e:	9c                   	pushf
528f     528f:	58                   	pop    %rax
5290     5290:	9c                   	pushf
5291     5291:	58                   	pop    %rax
5292     5292:	f3 0f b8 c7          	popcnt %edi,%eax
5296     5296:	f3 48 0f b8 c7       	popcnt %rdi,%rax
529b     529b:	f3 48 0f b8 c7       	popcnt %rdi,%rax
52a0     52a0:	f3 0f b8 c7          	popcnt %edi,%eax
52a4     52a4:	e8 00 00 00 00       	call   52a9 <.altinstr_replacement+0x52a9>	52a5: R_X86_64_PLT32	clear_page_rep-0x4
52a9     52a9:	e8 00 00 00 00       	call   52ae <.altinstr_replacement+0x52ae>	52aa: R_X86_64_PLT32	clear_page_erms-0x4
52ae     52ae:	9c                   	pushf
52af     52af:	58                   	pop    %rax
52b0     52b0:	fa                   	cli
52b1     52b1:	9c                   	pushf
52b2     52b2:	58                   	pop    %rax
52b3     52b3:	fa                   	cli
52b4     52b4:	9c                   	pushf
52b5     52b5:	58                   	pop    %rax
52b6     52b6:	fa                   	cli
52b7     52b7:	9c                   	pushf
52b8     52b8:	58                   	pop    %rax
52b9     52b9:	fb                   	sti
52ba     52ba:	e9 00 00 00 00       	jmp    52bf <.altinstr_replacement+0x52bf>	52bb: R_X86_64_PC32	.text+0x8d512cd
52bf     52bf:	e9 00 00 00 00       	jmp    52c4 <.altinstr_replacement+0x52c4>	52c0: R_X86_64_PC32	.text+0x8d512d8
52c4     52c4:	9c                   	pushf
52c5     52c5:	58                   	pop    %rax
52c6     52c6:	fa                   	cli
52c7     52c7:	9c                   	pushf
52c8     52c8:	58                   	pop    %rax
52c9     52c9:	fb                   	sti
52ca     52ca:	9c                   	pushf
52cb     52cb:	58                   	pop    %rax
52cc     52cc:	fb                   	sti
52cd     52cd:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
52d7     52d7:	f3 0f b8 c7          	popcnt %edi,%eax
52db     52db:	f3 0f b8 c7          	popcnt %edi,%eax
52df     52df:	f3 0f b8 c7          	popcnt %edi,%eax
52e3     52e3:	f3 48 0f b8 c7       	popcnt %rdi,%rax
52e8     52e8:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
52f2     52f2:	0f 01 cb             	stac
52f5     52f5:	e8 00 00 00 00       	call   52fa <.altinstr_replacement+0x52fa>	52f6: R_X86_64_PLT32	clear_user_erms-0x4
52fa     52fa:	e8 00 00 00 00       	call   52ff <.altinstr_replacement+0x52ff>	52fb: R_X86_64_PLT32	clear_user_rep_good-0x4
52ff     52ff:	e8 00 00 00 00       	call   5304 <.altinstr_replacement+0x5304>	5300: R_X86_64_PLT32	clear_user_original-0x4
5304     5304:	0f 01 ca             	clac
5307     5307:	9c                   	pushf
5308     5308:	58                   	pop    %rax
5309     5309:	fa                   	cli
530a     530a:	9c                   	pushf
530b     530b:	58                   	pop    %rax
530c     530c:	fb                   	sti
530d     530d:	9c                   	pushf
530e     530e:	58                   	pop    %rax
530f     530f:	9c                   	pushf
5310     5310:	58                   	pop    %rax
5311     5311:	9c                   	pushf
5312     5312:	58                   	pop    %rax
5313     5313:	9c                   	pushf
5314     5314:	58                   	pop    %rax
5315     5315:	9c                   	pushf
5316     5316:	58                   	pop    %rax
5317     5317:	9c                   	pushf
5318     5318:	58                   	pop    %rax
5319     5319:	9c                   	pushf
531a     531a:	58                   	pop    %rax
531b     531b:	9c                   	pushf
531c     531c:	58                   	pop    %rax
531d     531d:	9c                   	pushf
531e     531e:	58                   	pop    %rax
531f     531f:	9c                   	pushf
5320     5320:	58                   	pop    %rax
5321     5321:	9c                   	pushf
5322     5322:	58                   	pop    %rax
5323     5323:	fa                   	cli
5324     5324:	9c                   	pushf
5325     5325:	58                   	pop    %rax
5326     5326:	fb                   	sti
5327     5327:	9c                   	pushf
5328     5328:	58                   	pop    %rax
5329     5329:	fb                   	sti
532a     532a:	9c                   	pushf
532b     532b:	58                   	pop    %rax
532c     532c:	fb                   	sti
532d     532d:	e9 00 00 00 00       	jmp    5332 <.altinstr_replacement+0x5332>	532e: R_X86_64_PC32	.text+0x91b27b6
5332     5332:	0f 01 d9             	vmmcall
5335     5335:	e9 00 00 00 00       	jmp    533a <.altinstr_replacement+0x533a>	5336: R_X86_64_PC32	.text+0x91b28d8
533a     533a:	0f 01 d9             	vmmcall
533d     533d:	e9 00 00 00 00       	jmp    5342 <.altinstr_replacement+0x5342>	533e: R_X86_64_PC32	.text+0x91b2b0a
5342     5342:	0f 01 d9             	vmmcall
5345     5345:	0f 01 c1             	vmcall
5348     5348:	0f 01 d9             	vmmcall
534b     534b:	9c                   	pushf
534c     534c:	58                   	pop    %rax
534d     534d:	fa                   	cli
534e     534e:	9c                   	pushf
534f     534f:	58                   	pop    %rax
5350     5350:	fb                   	sti
5351     5351:	9c                   	pushf
5352     5352:	58                   	pop    %rax
5353     5353:	fa                   	cli
5354     5354:	9c                   	pushf
5355     5355:	58                   	pop    %rax
5356     5356:	fb                   	sti
5357     5357:	9c                   	pushf
5358     5358:	58                   	pop    %rax
5359     5359:	fa                   	cli
535a     535a:	9c                   	pushf
535b     535b:	58                   	pop    %rax
535c     535c:	fb                   	sti
535d     535d:	f3 0f b8 c7          	popcnt %edi,%eax
5361     5361:	f3 48 0f b8 c7       	popcnt %rdi,%rax
5366     5366:	f3 0f b8 c7          	popcnt %edi,%eax
536a     536a:	f3 0f b8 c7          	popcnt %edi,%eax
536e     536e:	f3 0f b8 c7          	popcnt %edi,%eax
5372     5372:	f3 0f b8 c7          	popcnt %edi,%eax
5376     5376:	f3 0f b8 c7          	popcnt %edi,%eax
537a     537a:	f3 0f b8 c7          	popcnt %edi,%eax
537e     537e:	f3 0f b8 c7          	popcnt %edi,%eax
5382     5382:	e9 00 00 00 00       	jmp    5387 <.altinstr_replacement+0x5387>	5383: R_X86_64_PC32	.text+0x9457d27
5387     5387:	f3 0f b8 c7          	popcnt %edi,%eax
538b     538b:	9c                   	pushf
538c     538c:	58                   	pop    %rax
538d     538d:	fa                   	cli
538e     538e:	9c                   	pushf
538f     538f:	58                   	pop    %rax
5390     5390:	fb                   	sti
5391     5391:	e8 00 00 00 00       	call   5396 <.altinstr_replacement+0x5396>	5392: R_X86_64_PLT32	clear_page_rep-0x4
5396     5396:	e8 00 00 00 00       	call   539b <.altinstr_replacement+0x539b>	5397: R_X86_64_PLT32	clear_page_erms-0x4
539b     539b:	e8 00 00 00 00       	call   53a0 <.altinstr_replacement+0x53a0>	539c: R_X86_64_PLT32	clear_page_rep-0x4
53a0     53a0:	e8 00 00 00 00       	call   53a5 <.altinstr_replacement+0x53a5>	53a1: R_X86_64_PLT32	clear_page_erms-0x4
53a5     53a5:	e8 00 00 00 00       	call   53aa <.altinstr_replacement+0x53aa>	53a6: R_X86_64_PLT32	clear_page_rep-0x4
53aa     53aa:	e8 00 00 00 00       	call   53af <.altinstr_replacement+0x53af>	53ab: R_X86_64_PLT32	clear_page_erms-0x4
53af     53af:	e8 00 00 00 00       	call   53b4 <.altinstr_replacement+0x53b4>	53b0: R_X86_64_PLT32	clear_page_rep-0x4
53b4     53b4:	e8 00 00 00 00       	call   53b9 <.altinstr_replacement+0x53b9>	53b5: R_X86_64_PLT32	clear_page_erms-0x4
53b9     53b9:	9c                   	pushf
53ba     53ba:	58                   	pop    %rax
53bb     53bb:	fa                   	cli
53bc     53bc:	9c                   	pushf
53bd     53bd:	58                   	pop    %rax
53be     53be:	fb                   	sti
53bf     53bf:	f3 0f b8 c7          	popcnt %edi,%eax
53c3     53c3:	9c                   	pushf
53c4     53c4:	58                   	pop    %rax
53c5     53c5:	fa                   	cli
53c6     53c6:	9c                   	pushf
53c7     53c7:	58                   	pop    %rax
53c8     53c8:	fb                   	sti
53c9     53c9:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
53d3     53d3:	0f 01 cb             	stac
53d6     53d6:	e8 00 00 00 00       	call   53db <.altinstr_replacement+0x53db>	53d7: R_X86_64_PLT32	clear_user_erms-0x4
53db     53db:	e8 00 00 00 00       	call   53e0 <.altinstr_replacement+0x53e0>	53dc: R_X86_64_PLT32	clear_user_rep_good-0x4
53e0     53e0:	e8 00 00 00 00       	call   53e5 <.altinstr_replacement+0x53e5>	53e1: R_X86_64_PLT32	clear_user_original-0x4
53e5     53e5:	0f 01 ca             	clac
53e8     53e8:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
53f2     53f2:	0f 01 cb             	stac
53f5     53f5:	e8 00 00 00 00       	call   53fa <.altinstr_replacement+0x53fa>	53f6: R_X86_64_PLT32	clear_user_erms-0x4
53fa     53fa:	e8 00 00 00 00       	call   53ff <.altinstr_replacement+0x53ff>	53fb: R_X86_64_PLT32	clear_user_rep_good-0x4
53ff     53ff:	e8 00 00 00 00       	call   5404 <.altinstr_replacement+0x5404>	5400: R_X86_64_PLT32	clear_user_original-0x4
5404     5404:	0f 01 ca             	clac
5407     5407:	e9 00 00 00 00       	jmp    540c <.altinstr_replacement+0x540c>	5408: R_X86_64_PC32	.text+0x95bd41c
540c     540c:	9c                   	pushf
540d     540d:	58                   	pop    %rax
540e     540e:	fa                   	cli
540f     540f:	fb                   	sti
5410     5410:	9c                   	pushf
5411     5411:	58                   	pop    %rax
5412     5412:	fa                   	cli
5413     5413:	fb                   	sti
5414     5414:	9c                   	pushf
5415     5415:	58                   	pop    %rax
5416     5416:	fa                   	cli
5417     5417:	fb                   	sti
5418     5418:	e9 00 00 00 00       	jmp    541d <.altinstr_replacement+0x541d>	5419: R_X86_64_PC32	.init.text+0x2ac924
541d     541d:	e9 00 00 00 00       	jmp    5422 <.altinstr_replacement+0x5422>	541e: R_X86_64_PC32	.init.text+0x2ac97a
5422     5422:	e9 00 00 00 00       	jmp    5427 <.altinstr_replacement+0x5427>	5423: R_X86_64_PC32	.init.text+0x2ac9fd
5427     5427:	e9 00 00 00 00       	jmp    542c <.altinstr_replacement+0x542c>	5428: R_X86_64_PC32	.init.text+0x2aca4a
542c     542c:	9c                   	pushf
542d     542d:	58                   	pop    %rax
542e     542e:	f3 0f b8 c7          	popcnt %edi,%eax
5432     5432:	f3 0f b8 c7          	popcnt %edi,%eax
5436     5436:	f3 0f b8 c7          	popcnt %edi,%eax
543a     543a:	e8 00 00 00 00       	call   543f <.altinstr_replacement+0x543f>	543b: R_X86_64_PLT32	clear_page_rep-0x4
543f     543f:	e8 00 00 00 00       	call   5444 <.altinstr_replacement+0x5444>	5440: R_X86_64_PLT32	clear_page_erms-0x4
5444     5444:	e8 00 00 00 00       	call   5449 <.altinstr_replacement+0x5449>	5445: R_X86_64_PLT32	clear_page_rep-0x4
5449     5449:	e8 00 00 00 00       	call   544e <.altinstr_replacement+0x544e>	544a: R_X86_64_PLT32	clear_page_erms-0x4
544e     544e:	e9 00 00 00 00       	jmp    5453 <.altinstr_replacement+0x5453>	544f: R_X86_64_PC32	.text+0x96a0dae
5453     5453:	66 41 0f ae 3c 24    	clflushopt (%r12)
5459     5459:	9c                   	pushf
545a     545a:	58                   	pop    %rax
545b     545b:	fa                   	cli
545c     545c:	9c                   	pushf
545d     545d:	58                   	pop    %rax
545e     545e:	fb                   	sti
545f     545f:	9c                   	pushf
5460     5460:	58                   	pop    %rax
5461     5461:	fa                   	cli
5462     5462:	9c                   	pushf
5463     5463:	58                   	pop    %rax
5464     5464:	fb                   	sti
5465     5465:	9c                   	pushf
5466     5466:	58                   	pop    %rax
5467     5467:	fa                   	cli
5468     5468:	9c                   	pushf
5469     5469:	58                   	pop    %rax
546a     546a:	fb                   	sti
546b     546b:	9c                   	pushf
546c     546c:	58                   	pop    %rax
546d     546d:	fa                   	cli
546e     546e:	9c                   	pushf
546f     546f:	58                   	pop    %rax
5470     5470:	fb                   	sti
5471     5471:	e9 00 00 00 00       	jmp    5476 <.altinstr_replacement+0x5476>	5472: R_X86_64_PC32	.text+0x979f9a8
5476     5476:	e9 00 00 00 00       	jmp    547b <.altinstr_replacement+0x547b>	5477: R_X86_64_PC32	.text+0x979f7fa
547b     547b:	9c                   	pushf
547c     547c:	58                   	pop    %rax
547d     547d:	fa                   	cli
547e     547e:	9c                   	pushf
547f     547f:	58                   	pop    %rax
5480     5480:	fb                   	sti
5481     5481:	e9 00 00 00 00       	jmp    5486 <.altinstr_replacement+0x5486>	5482: R_X86_64_PC32	.init.text+0x2b24f7
5486     5486:	e9 00 00 00 00       	jmp    548b <.altinstr_replacement+0x548b>	5487: R_X86_64_PC32	.init.text+0x2b30c4
548b     548b:	e9 00 00 00 00       	jmp    5490 <.altinstr_replacement+0x5490>	548c: R_X86_64_PC32	.init.text+0x2b3383
5490     5490:	f3 0f b8 c7          	popcnt %edi,%eax
5494     5494:	f3 48 0f b8 c7       	popcnt %rdi,%rax
5499     5499:	0f 09                	wbinvd
549b     549b:	f3 48 0f b8 c7       	popcnt %rdi,%rax
54a0     54a0:	f3 0f b8 c7          	popcnt %edi,%eax
54a4     54a4:	f3 0f b8 c7          	popcnt %edi,%eax
54a8     54a8:	f3 0f b8 c7          	popcnt %edi,%eax
54ac     54ac:	e9 00 00 00 00       	jmp    54b1 <.altinstr_replacement+0x54b1>	54ad: R_X86_64_PC32	.init.text+0x2b58dc
54b1     54b1:	e9 00 00 00 00       	jmp    54b6 <.altinstr_replacement+0x54b6>	54b2: R_X86_64_PC32	.init.text+0x2b62e6
54b6     54b6:	9c                   	pushf
54b7     54b7:	58                   	pop    %rax
54b8     54b8:	9c                   	pushf
54b9     54b9:	58                   	pop    %rax
54ba     54ba:	fa                   	cli
54bb     54bb:	9c                   	pushf
54bc     54bc:	58                   	pop    %rax
54bd     54bd:	9c                   	pushf
54be     54be:	58                   	pop    %rax
54bf     54bf:	fb                   	sti
54c0     54c0:	fb                   	sti
54c1     54c1:	9c                   	pushf
54c2     54c2:	58                   	pop    %rax
54c3     54c3:	fa                   	cli
54c4     54c4:	9c                   	pushf
54c5     54c5:	58                   	pop    %rax
54c6     54c6:	fb                   	sti
54c7     54c7:	9c                   	pushf
54c8     54c8:	58                   	pop    %rax
54c9     54c9:	fa                   	cli
54ca     54ca:	9c                   	pushf
54cb     54cb:	58                   	pop    %rax
54cc     54cc:	fb                   	sti
54cd     54cd:	9c                   	pushf
54ce     54ce:	58                   	pop    %rax
54cf     54cf:	fb                   	sti
54d0     54d0:	9c                   	pushf
54d1     54d1:	58                   	pop    %rax
54d2     54d2:	9c                   	pushf
54d3     54d3:	58                   	pop    %rax
54d4     54d4:	fa                   	cli
54d5     54d5:	fb                   	sti
54d6     54d6:	9c                   	pushf
54d7     54d7:	58                   	pop    %rax
54d8     54d8:	fb                   	sti
54d9     54d9:	9c                   	pushf
54da     54da:	58                   	pop    %rax
54db     54db:	fa                   	cli
54dc     54dc:	fb                   	sti
54dd     54dd:	fb                   	sti
54de     54de:	9c                   	pushf
54df     54df:	58                   	pop    %rax
54e0     54e0:	fa                   	cli
54e1     54e1:	9c                   	pushf
54e2     54e2:	58                   	pop    %rax
54e3     54e3:	fb                   	sti
54e4     54e4:	9c                   	pushf
54e5     54e5:	58                   	pop    %rax
54e6     54e6:	fa                   	cli
54e7     54e7:	9c                   	pushf
54e8     54e8:	58                   	pop    %rax
54e9     54e9:	fb                   	sti
54ea     54ea:	9c                   	pushf
54eb     54eb:	58                   	pop    %rax
54ec     54ec:	fb                   	sti
54ed     54ed:	9c                   	pushf
54ee     54ee:	58                   	pop    %rax
54ef     54ef:	fa                   	cli
54f0     54f0:	9c                   	pushf
54f1     54f1:	58                   	pop    %rax
54f2     54f2:	fa                   	cli
54f3     54f3:	9c                   	pushf
54f4     54f4:	58                   	pop    %rax
54f5     54f5:	fb                   	sti
54f6     54f6:	9c                   	pushf
54f7     54f7:	58                   	pop    %rax
54f8     54f8:	fa                   	cli
54f9     54f9:	9c                   	pushf
54fa     54fa:	58                   	pop    %rax
54fb     54fb:	fb                   	sti
54fc     54fc:	9c                   	pushf
54fd     54fd:	58                   	pop    %rax
54fe     54fe:	fa                   	cli
54ff     54ff:	9c                   	pushf
5500     5500:	58                   	pop    %rax
5501     5501:	fb                   	sti
5502     5502:	9c                   	pushf
5503     5503:	58                   	pop    %rax
5504     5504:	fa                   	cli
5505     5505:	9c                   	pushf
5506     5506:	58                   	pop    %rax
5507     5507:	fb                   	sti
5508     5508:	9c                   	pushf
5509     5509:	58                   	pop    %rax
550a     550a:	fa                   	cli
550b     550b:	9c                   	pushf
550c     550c:	58                   	pop    %rax
550d     550d:	fb                   	sti
550e     550e:	e8 00 00 00 00       	call   5513 <.altinstr_replacement+0x5513>	550f: R_X86_64_PLT32	clear_page_rep-0x4
5513     5513:	e8 00 00 00 00       	call   5518 <.altinstr_replacement+0x5518>	5514: R_X86_64_PLT32	clear_page_erms-0x4
5518     5518:	9c                   	pushf
5519     5519:	58                   	pop    %rax
551a     551a:	fa                   	cli
551b     551b:	9c                   	pushf
551c     551c:	58                   	pop    %rax
551d     551d:	fb                   	sti
551e     551e:	9c                   	pushf
551f     551f:	58                   	pop    %rax
5520     5520:	fa                   	cli
5521     5521:	9c                   	pushf
5522     5522:	58                   	pop    %rax
5523     5523:	fb                   	sti
5524     5524:	9c                   	pushf
5525     5525:	58                   	pop    %rax
5526     5526:	fa                   	cli
5527     5527:	9c                   	pushf
5528     5528:	58                   	pop    %rax
5529     5529:	fb                   	sti
552a     552a:	9c                   	pushf
552b     552b:	58                   	pop    %rax
552c     552c:	fa                   	cli
552d     552d:	9c                   	pushf
552e     552e:	58                   	pop    %rax
552f     552f:	fb                   	sti
5530     5530:	f3 48 0f b8 c7       	popcnt %rdi,%rax
5535     5535:	9c                   	pushf
5536     5536:	58                   	pop    %rax
5537     5537:	fa                   	cli
5538     5538:	9c                   	pushf
5539     5539:	58                   	pop    %rax
553a     553a:	fb                   	sti
553b     553b:	49 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r13
5545     5545:	49 be 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r14
554f     554f:	0f 01 cb             	stac
5552     5552:	e8 00 00 00 00       	call   5557 <.altinstr_replacement+0x5557>	5553: R_X86_64_PLT32	clear_user_erms-0x4
5557     5557:	e8 00 00 00 00       	call   555c <.altinstr_replacement+0x555c>	5558: R_X86_64_PLT32	clear_user_rep_good-0x4
555c     555c:	e8 00 00 00 00       	call   5561 <.altinstr_replacement+0x5561>	555d: R_X86_64_PLT32	clear_user_original-0x4
5561     5561:	0f 01 ca             	clac
5564     5564:	49 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r13
556e     556e:	0f 01 cb             	stac
5571     5571:	e8 00 00 00 00       	call   5576 <.altinstr_replacement+0x5576>	5572: R_X86_64_PLT32	clear_user_erms-0x4
5576     5576:	e8 00 00 00 00       	call   557b <.altinstr_replacement+0x557b>	5577: R_X86_64_PLT32	clear_user_rep_good-0x4
557b     557b:	e8 00 00 00 00       	call   5580 <.altinstr_replacement+0x5580>	557c: R_X86_64_PLT32	clear_user_original-0x4
5580     5580:	0f 01 ca             	clac
5583     5583:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
558d     558d:	0f 01 cb             	stac
5590     5590:	e8 00 00 00 00       	call   5595 <.altinstr_replacement+0x5595>	5591: R_X86_64_PLT32	clear_user_erms-0x4
5595     5595:	e8 00 00 00 00       	call   559a <.altinstr_replacement+0x559a>	5596: R_X86_64_PLT32	clear_user_rep_good-0x4
559a     559a:	e8 00 00 00 00       	call   559f <.altinstr_replacement+0x559f>	559b: R_X86_64_PLT32	clear_user_original-0x4
559f     559f:	0f 01 ca             	clac
55a2     55a2:	e8 00 00 00 00       	call   55a7 <.altinstr_replacement+0x55a7>	55a3: R_X86_64_PLT32	clear_page_rep-0x4
55a7     55a7:	e8 00 00 00 00       	call   55ac <.altinstr_replacement+0x55ac>	55a8: R_X86_64_PLT32	clear_page_erms-0x4
55ac     55ac:	e8 00 00 00 00       	call   55b1 <.altinstr_replacement+0x55b1>	55ad: R_X86_64_PLT32	clear_page_rep-0x4
55b1     55b1:	e8 00 00 00 00       	call   55b6 <.altinstr_replacement+0x55b6>	55b2: R_X86_64_PLT32	clear_page_erms-0x4
55b6     55b6:	48 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbp
55c0     55c0:	9c                   	pushf
55c1     55c1:	58                   	pop    %rax
55c2     55c2:	fa                   	cli
55c3     55c3:	9c                   	pushf
55c4     55c4:	58                   	pop    %rax
55c5     55c5:	fb                   	sti
55c6     55c6:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
55d0     55d0:	f3 48 0f b8 c7       	popcnt %rdi,%rax
55d5     55d5:	9c                   	pushf
55d6     55d6:	58                   	pop    %rax
55d7     55d7:	fa                   	cli
55d8     55d8:	9c                   	pushf
55d9     55d9:	58                   	pop    %rax
55da     55da:	fb                   	sti
55db     55db:	9c                   	pushf
55dc     55dc:	58                   	pop    %rax
55dd     55dd:	fa                   	cli
55de     55de:	9c                   	pushf
55df     55df:	58                   	pop    %rax
55e0     55e0:	fb                   	sti
55e1     55e1:	f3 48 0f b8 c7       	popcnt %rdi,%rax
55e6     55e6:	f3 48 0f b8 c7       	popcnt %rdi,%rax
55eb     55eb:	f3 48 0f b8 c7       	popcnt %rdi,%rax
55f0     55f0:	f3 0f b8 c7          	popcnt %edi,%eax
55f4     55f4:	f3 0f b8 c7          	popcnt %edi,%eax
55f8     55f8:	f3 48 0f b8 c7       	popcnt %rdi,%rax
55fd     55fd:	9c                   	pushf
55fe     55fe:	58                   	pop    %rax
55ff     55ff:	fa                   	cli
5600     5600:	9c                   	pushf
5601     5601:	58                   	pop    %rax
5602     5602:	fb                   	sti
5603     5603:	9c                   	pushf
5604     5604:	58                   	pop    %rax
5605     5605:	fa                   	cli
5606     5606:	9c                   	pushf
5607     5607:	58                   	pop    %rax
5608     5608:	fb                   	sti
5609     5609:	9c                   	pushf
560a     560a:	58                   	pop    %rax
560b     560b:	fa                   	cli
560c     560c:	9c                   	pushf
560d     560d:	58                   	pop    %rax
560e     560e:	fb                   	sti
560f     560f:	9c                   	pushf
5610     5610:	58                   	pop    %rax
5611     5611:	fa                   	cli
5612     5612:	9c                   	pushf
5613     5613:	58                   	pop    %rax
5614     5614:	fb                   	sti
5615     5615:	9c                   	pushf
5616     5616:	58                   	pop    %rax
5617     5617:	fa                   	cli
5618     5618:	9c                   	pushf
5619     5619:	58                   	pop    %rax
561a     561a:	fb                   	sti
561b     561b:	9c                   	pushf
561c     561c:	58                   	pop    %rax
561d     561d:	fa                   	cli
561e     561e:	9c                   	pushf
561f     561f:	58                   	pop    %rax
5620     5620:	fb                   	sti
5621     5621:	9c                   	pushf
5622     5622:	58                   	pop    %rax
5623     5623:	fa                   	cli
5624     5624:	9c                   	pushf
5625     5625:	58                   	pop    %rax
5626     5626:	fb                   	sti
5627     5627:	9c                   	pushf
5628     5628:	58                   	pop    %rax
5629     5629:	fa                   	cli
562a     562a:	9c                   	pushf
562b     562b:	58                   	pop    %rax
562c     562c:	fb                   	sti
562d     562d:	9c                   	pushf
562e     562e:	58                   	pop    %rax
562f     562f:	9c                   	pushf
5630     5630:	58                   	pop    %rax
5631     5631:	f3 48 0f b8 c7       	popcnt %rdi,%rax
5636     5636:	9c                   	pushf
5637     5637:	58                   	pop    %rax
5638     5638:	9c                   	pushf
5639     5639:	58                   	pop    %rax
563a     563a:	fb                   	sti
563b     563b:	0f 30                	wrmsr
563d     563d:	0f 30                	wrmsr
563f     563f:	0f 30                	wrmsr
5641     5641:	0f 30                	wrmsr
5643     5643:	0f 30                	wrmsr
5645     5645:	0f 30                	wrmsr
5647     5647:	0f 30                	wrmsr
5649     5649:	0f 30                	wrmsr
564b     564b:	0f 30                	wrmsr
564d     564d:	0f 30                	wrmsr
564f     564f:	0f 30                	wrmsr
5651     5651:	0f 30                	wrmsr
5653     5653:	0f 30                	wrmsr
5655     5655:	0f 30                	wrmsr
5657     5657:	0f 30                	wrmsr
5659     5659:	0f 30                	wrmsr
565b     565b:	0f 30                	wrmsr
565d     565d:	0f 30                	wrmsr
565f     565f:	0f 30                	wrmsr
5661     5661:	0f 30                	wrmsr
5663     5663:	0f 30                	wrmsr
5665     5665:	0f 30                	wrmsr
5667     5667:	0f 30                	wrmsr
5669     5669:	0f 30                	wrmsr
566b     566b:	0f 30                	wrmsr
566d     566d:	0f 30                	wrmsr
566f     566f:	0f 30                	wrmsr
5671     5671:	0f 30                	wrmsr
5673     5673:	0f 30                	wrmsr
5675     5675:	0f 30                	wrmsr
5677     5677:	0f 30                	wrmsr
5679     5679:	0f 30                	wrmsr
567b     567b:	0f 30                	wrmsr
567d     567d:	0f 30                	wrmsr
567f     567f:	0f 30                	wrmsr
5681     5681:	0f 30                	wrmsr
5683     5683:	0f 30                	wrmsr
5685     5685:	0f 30                	wrmsr
5687     5687:	0f 30                	wrmsr
5689     5689:	0f 30                	wrmsr
568b     568b:	0f 30                	wrmsr
568d     568d:	0f 30                	wrmsr
568f     568f:	f3 48 0f b8 c7       	popcnt %rdi,%rax
5694     5694:	f3 48 0f b8 c7       	popcnt %rdi,%rax
5699     5699:	f3 48 0f b8 c7       	popcnt %rdi,%rax
569e     569e:	f3 48 0f b8 c7       	popcnt %rdi,%rax
56a3     56a3:	f3 0f b8 c7          	popcnt %edi,%eax
56a7     56a7:	f3 0f b8 c7          	popcnt %edi,%eax
56ab     56ab:	f3 0f b8 c7          	popcnt %edi,%eax
56af     56af:	f3 0f b8 c7          	popcnt %edi,%eax
56b3     56b3:	f3 0f b8 c7          	popcnt %edi,%eax
56b7     56b7:	f3 0f b8 c7          	popcnt %edi,%eax
56bb     56bb:	f3 0f b8 c7          	popcnt %edi,%eax
56bf     56bf:	f3 0f b8 c7          	popcnt %edi,%eax
56c3     56c3:	f3 0f b8 c7          	popcnt %edi,%eax
56c7     56c7:	0f ae e8             	lfence
56ca     56ca:	0f 31                	rdtsc
56cc     56cc:	0f 01 f9             	rdtscp
56cf     56cf:	9c                   	pushf
56d0     56d0:	58                   	pop    %rax
56d1     56d1:	fa                   	cli
56d2     56d2:	9c                   	pushf
56d3     56d3:	58                   	pop    %rax
56d4     56d4:	fb                   	sti
56d5     56d5:	9c                   	pushf
56d6     56d6:	58                   	pop    %rax
56d7     56d7:	fa                   	cli
56d8     56d8:	9c                   	pushf
56d9     56d9:	58                   	pop    %rax
56da     56da:	fb                   	sti
56db     56db:	e8 00 00 00 00       	call   56e0 <.altinstr_replacement+0x56e0>	56dc: R_X86_64_PLT32	copy_user_generic_string-0x4
56e0     56e0:	e8 00 00 00 00       	call   56e5 <.altinstr_replacement+0x56e5>	56e1: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
56e5     56e5:	e8 00 00 00 00       	call   56ea <.altinstr_replacement+0x56ea>	56e6: R_X86_64_PLT32	copy_user_generic_string-0x4
56ea     56ea:	e8 00 00 00 00       	call   56ef <.altinstr_replacement+0x56ef>	56eb: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
56ef     56ef:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
56f9     56f9:	48 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbp
5703     5703:	49 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r13
570d     570d:	49 bf 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r15
5717     5717:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
5721     5721:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
572b     572b:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
5735     5735:	e8 00 00 00 00       	call   573a <.altinstr_replacement+0x573a>	5736: R_X86_64_PLT32	copy_user_generic_string-0x4
573a     573a:	e8 00 00 00 00       	call   573f <.altinstr_replacement+0x573f>	573b: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
573f     573f:	e8 00 00 00 00       	call   5744 <.altinstr_replacement+0x5744>	5740: R_X86_64_PLT32	copy_user_generic_string-0x4
5744     5744:	e8 00 00 00 00       	call   5749 <.altinstr_replacement+0x5749>	5745: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
5749     5749:	e8 00 00 00 00       	call   574e <.altinstr_replacement+0x574e>	574a: R_X86_64_PLT32	copy_user_generic_string-0x4
574e     574e:	e8 00 00 00 00       	call   5753 <.altinstr_replacement+0x5753>	574f: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
5753     5753:	e8 00 00 00 00       	call   5758 <.altinstr_replacement+0x5758>	5754: R_X86_64_PLT32	copy_user_generic_string-0x4
5758     5758:	e8 00 00 00 00       	call   575d <.altinstr_replacement+0x575d>	5759: R_X86_64_PLT32	copy_user_enhanced_fast_string-0x4
575d     575d:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
5767     5767:	0f 09                	wbinvd
5769     5769:	0f 09                	wbinvd
576b     576b:	0f 09                	wbinvd
576d     576d:	f3 0f b8 c7          	popcnt %edi,%eax
5771     5771:	f3 0f b8 c7          	popcnt %edi,%eax
5775     5775:	e9 00 00 00 00       	jmp    577a <.altinstr_replacement+0x577a>	5776: R_X86_64_PC32	.init.text+0x3184b9
577a     577a:	49 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r13
5784     5784:	9c                   	pushf
5785     5785:	58                   	pop    %rax
5786     5786:	fa                   	cli
5787     5787:	9c                   	pushf
5788     5788:	58                   	pop    %rax
5789     5789:	9c                   	pushf
578a     578a:	58                   	pop    %rax
578b     578b:	fa                   	cli
578c     578c:	fb                   	sti
578d     578d:	f3 0f b8 c7          	popcnt %edi,%eax
5791     5791:	f3 0f b8 c7          	popcnt %edi,%eax
5795     5795:	f3 0f b8 c7          	popcnt %edi,%eax
5799     5799:	f3 0f b8 c7          	popcnt %edi,%eax
579d     579d:	48 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbp
57a7     57a7:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
57b1     57b1:	e8 00 00 00 00       	call   57b6 <.altinstr_replacement+0x57b6>	57b2: R_X86_64_PLT32	__x86_indirect_thunk_rbp-0x4
57b6     57b6:	0f ae e8             	lfence
57b9     57b9:	ff d5                	call   *%rbp
57bb     57bb:	e8 00 00 00 00       	call   57c0 <.altinstr_replacement+0x57c0>	57bc: R_X86_64_PLT32	__x86_indirect_thunk_rax-0x4
57c0     57c0:	0f ae e8             	lfence
57c3     57c3:	ff d0                	call   *%rax
57c5     57c5:	9c                   	pushf
57c6     57c6:	58                   	pop    %rax
57c7     57c7:	fa                   	cli
57c8     57c8:	9c                   	pushf
57c9     57c9:	58                   	pop    %rax
57ca     57ca:	fb                   	sti
57cb     57cb:	e8 00 00 00 00       	call   57d0 <.altinstr_replacement+0x57d0>	57cc: R_X86_64_PLT32	__x86_indirect_thunk_r13-0x4
57d0     57d0:	0f ae e8             	lfence
57d3     57d3:	41 ff d5             	call   *%r13
57d6     57d6:	9c                   	pushf
57d7     57d7:	58                   	pop    %rax
57d8     57d8:	fb                   	sti
57d9     57d9:	e9 00 00 00 00       	jmp    57de <.altinstr_replacement+0x57de>	57da: R_X86_64_PC32	.text+0xa73ce61
57de     57de:	e8 00 00 00 00       	call   57e3 <.altinstr_replacement+0x57e3>	57df: R_X86_64_PLT32	__x86_indirect_thunk_r13-0x4
57e3     57e3:	0f ae e8             	lfence
57e6     57e6:	41 ff d5             	call   *%r13
57e9     57e9:	9c                   	pushf
57ea     57ea:	58                   	pop    %rax
57eb     57eb:	9c                   	pushf
57ec     57ec:	58                   	pop    %rax
57ed     57ed:	fa                   	cli
57ee     57ee:	9c                   	pushf
57ef     57ef:	58                   	pop    %rax
57f0     57f0:	fb                   	sti
57f1     57f1:	f3 0f b8 c7          	popcnt %edi,%eax
57f5     57f5:	f3 48 0f b8 c7       	popcnt %rdi,%rax
57fa     57fa:	f3 48 0f b8 c7       	popcnt %rdi,%rax
57ff     57ff:	9c                   	pushf
5800     5800:	58                   	pop    %rax
5801     5801:	fa                   	cli
5802     5802:	9c                   	pushf
5803     5803:	58                   	pop    %rax
5804     5804:	fb                   	sti
5805     5805:	f3 0f b8 c7          	popcnt %edi,%eax
5809     5809:	f3 48 0f b8 c7       	popcnt %rdi,%rax
580e     580e:	f3 48 0f b8 c7       	popcnt %rdi,%rax
5813     5813:	f3 0f b8 c7          	popcnt %edi,%eax
5817     5817:	f3 0f b8 c7          	popcnt %edi,%eax
581b     581b:	f3 0f b8 c7          	popcnt %edi,%eax
581f     581f:	f3 0f b8 c7          	popcnt %edi,%eax
5823     5823:	f3 48 0f b8 c7       	popcnt %rdi,%rax
5828     5828:	f3 0f b8 c7          	popcnt %edi,%eax
582c     582c:	f3 48 0f b8 c7       	popcnt %rdi,%rax
5831     5831:	f3 48 0f b8 c7       	popcnt %rdi,%rax
5836     5836:	e9 00 00 00 00       	jmp    583b <.altinstr_replacement+0x583b>	5837: R_X86_64_PC32	.text+0xa9af808
583b     583b:	e9 00 00 00 00       	jmp    5840 <.altinstr_replacement+0x5840>	583c: R_X86_64_PC32	.text+0xa9af7fd
5840     5840:	49 bc 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r12
584a     584a:	9c                   	pushf
584b     584b:	58                   	pop    %rax
584c     584c:	fa                   	cli
584d     584d:	9c                   	pushf
584e     584e:	58                   	pop    %rax
584f     584f:	fb                   	sti
5850     5850:	9c                   	pushf
5851     5851:	58                   	pop    %rax
5852     5852:	fa                   	cli
5853     5853:	9c                   	pushf
5854     5854:	58                   	pop    %rax
5855     5855:	fb                   	sti
5856     5856:	9c                   	pushf
5857     5857:	58                   	pop    %rax
5858     5858:	fb                   	sti
5859     5859:	9c                   	pushf
585a     585a:	58                   	pop    %rax
585b     585b:	fa                   	cli
585c     585c:	9c                   	pushf
585d     585d:	58                   	pop    %rax
585e     585e:	fb                   	sti
585f     585f:	9c                   	pushf
5860     5860:	58                   	pop    %rax
5861     5861:	fa                   	cli
5862     5862:	9c                   	pushf
5863     5863:	58                   	pop    %rax
5864     5864:	fb                   	sti
5865     5865:	9c                   	pushf
5866     5866:	58                   	pop    %rax
5867     5867:	fa                   	cli
5868     5868:	9c                   	pushf
5869     5869:	58                   	pop    %rax
586a     586a:	fb                   	sti
586b     586b:	9c                   	pushf
586c     586c:	58                   	pop    %rax
586d     586d:	fa                   	cli
586e     586e:	9c                   	pushf
586f     586f:	58                   	pop    %rax
5870     5870:	fb                   	sti
5871     5871:	9c                   	pushf
5872     5872:	58                   	pop    %rax
5873     5873:	fa                   	cli
5874     5874:	9c                   	pushf
5875     5875:	58                   	pop    %rax
5876     5876:	fb                   	sti
5877     5877:	9c                   	pushf
5878     5878:	58                   	pop    %rax
5879     5879:	fa                   	cli
587a     587a:	9c                   	pushf
587b     587b:	58                   	pop    %rax
587c     587c:	fb                   	sti
587d     587d:	9c                   	pushf
587e     587e:	58                   	pop    %rax
587f     587f:	fa                   	cli
5880     5880:	9c                   	pushf
5881     5881:	58                   	pop    %rax
5882     5882:	fb                   	sti
5883     5883:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
588d     588d:	49 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r13
5897     5897:	0f 01 cb             	stac
589a     589a:	e8 00 00 00 00       	call   589f <.altinstr_replacement+0x589f>	589b: R_X86_64_PLT32	clear_user_erms-0x4
589f     589f:	e8 00 00 00 00       	call   58a4 <.altinstr_replacement+0x58a4>	58a0: R_X86_64_PLT32	clear_user_rep_good-0x4
58a4     58a4:	e8 00 00 00 00       	call   58a9 <.altinstr_replacement+0x58a9>	58a5: R_X86_64_PLT32	clear_user_original-0x4
58a9     58a9:	0f 01 ca             	clac
58ac     58ac:	49 bd 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r13
58b6     58b6:	9c                   	pushf
58b7     58b7:	58                   	pop    %rax
58b8     58b8:	fa                   	cli
58b9     58b9:	fb                   	sti
58ba     58ba:	9c                   	pushf
58bb     58bb:	58                   	pop    %rax
58bc     58bc:	9c                   	pushf
58bd     58bd:	58                   	pop    %rax
58be     58be:	9c                   	pushf
58bf     58bf:	58                   	pop    %rax
58c0     58c0:	9c                   	pushf
58c1     58c1:	58                   	pop    %rax
58c2     58c2:	9c                   	pushf
58c3     58c3:	58                   	pop    %rax
58c4     58c4:	9c                   	pushf
58c5     58c5:	58                   	pop    %rax
58c6     58c6:	9c                   	pushf
58c7     58c7:	58                   	pop    %rax
58c8     58c8:	9c                   	pushf
58c9     58c9:	58                   	pop    %rax
58ca     58ca:	9c                   	pushf
58cb     58cb:	58                   	pop    %rax
58cc     58cc:	9c                   	pushf
58cd     58cd:	58                   	pop    %rax
58ce     58ce:	9c                   	pushf
58cf     58cf:	58                   	pop    %rax
58d0     58d0:	fb                   	sti
58d1     58d1:	f3 0f b8 c7          	popcnt %edi,%eax
58d5     58d5:	f3 0f b8 c7          	popcnt %edi,%eax
58d9     58d9:	f3 0f b8 c7          	popcnt %edi,%eax
58dd     58dd:	f3 0f b8 c7          	popcnt %edi,%eax
58e1     58e1:	f3 48 0f b8 c7       	popcnt %rdi,%rax
58e6     58e6:	f3 0f b8 c7          	popcnt %edi,%eax
58ea     58ea:	f3 0f b8 c7          	popcnt %edi,%eax
58ee     58ee:	f3 48 0f b8 c7       	popcnt %rdi,%rax
58f3     58f3:	f3 48 0f b8 c7       	popcnt %rdi,%rax
58f8     58f8:	f3 48 0f b8 c7       	popcnt %rdi,%rax
58fd     58fd:	f3 48 0f b8 c7       	popcnt %rdi,%rax
5902     5902:	f3 48 0f b8 c7       	popcnt %rdi,%rax
5907     5907:	f3 0f b8 c7          	popcnt %edi,%eax
590b     590b:	f3 0f b8 c7          	popcnt %edi,%eax
590f     590f:	f3 0f b8 c7          	popcnt %edi,%eax
5913     5913:	f3 0f b8 c7          	popcnt %edi,%eax
5917     5917:	f3 0f b8 c7          	popcnt %edi,%eax
591b     591b:	f3 0f b8 c7          	popcnt %edi,%eax
591f     591f:	f3 0f b8 c7          	popcnt %edi,%eax
5923     5923:	f3 0f b8 c7          	popcnt %edi,%eax
5927     5927:	f3 0f b8 c7          	popcnt %edi,%eax
592b     592b:	f3 0f b8 c7          	popcnt %edi,%eax
592f     592f:	f3 0f b8 c7          	popcnt %edi,%eax
5933     5933:	f3 48 0f b8 c7       	popcnt %rdi,%rax
5938     5938:	f3 48 0f b8 c7       	popcnt %rdi,%rax
593d     593d:	f3 48 0f b8 c7       	popcnt %rdi,%rax
5942     5942:	f3 48 0f b8 c7       	popcnt %rdi,%rax
5947     5947:	f3 48 0f b8 c7       	popcnt %rdi,%rax
594c     594c:	f3 48 0f b8 c7       	popcnt %rdi,%rax
5951     5951:	f3 48 0f b8 c7       	popcnt %rdi,%rax
5956     5956:	f3 48 0f b8 c7       	popcnt %rdi,%rax
595b     595b:	f3 48 0f b8 c7       	popcnt %rdi,%rax
5960     5960:	f3 48 0f b8 c7       	popcnt %rdi,%rax
5965     5965:	f3 48 0f b8 c7       	popcnt %rdi,%rax
596a     596a:	f3 48 0f b8 c7       	popcnt %rdi,%rax
596f     596f:	f3 48 0f b8 c7       	popcnt %rdi,%rax
5974     5974:	f3 48 0f b8 c7       	popcnt %rdi,%rax
5979     5979:	f3 48 0f b8 c7       	popcnt %rdi,%rax
597e     597e:	9c                   	pushf
597f     597f:	58                   	pop    %rax
5980     5980:	41 0f 0d 0c 24       	prefetchw (%r12)
5985     5985:	41 0f 0d 4c 05 00    	prefetchw 0x0(%r13,%rax,1)
598b     598b:	9c                   	pushf
598c     598c:	58                   	pop    %rax
598d     598d:	48 b8 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rax
5997     5997:	0f 01 cb             	stac
599a     599a:	0f ae e8             	lfence
599d     599d:	0f 01 ca             	clac
59a0     59a0:	0f 01 ca             	clac
59a3     59a3:	9c                   	pushf
59a4     59a4:	58                   	pop    %rax
59a5     59a5:	fa                   	cli
59a6     59a6:	9c                   	pushf
59a7     59a7:	58                   	pop    %rax
59a8     59a8:	fb                   	sti
59a9     59a9:	9c                   	pushf
59aa     59aa:	58                   	pop    %rax
59ab     59ab:	fa                   	cli
59ac     59ac:	9c                   	pushf
59ad     59ad:	58                   	pop    %rax
59ae     59ae:	fb                   	sti
59af     59af:	9c                   	pushf
59b0     59b0:	58                   	pop    %rax
59b1     59b1:	fa                   	cli
59b2     59b2:	9c                   	pushf
59b3     59b3:	58                   	pop    %rax
59b4     59b4:	fb                   	sti
59b5     59b5:	9c                   	pushf
59b6     59b6:	58                   	pop    %rax
59b7     59b7:	fb                   	sti
59b8     59b8:	fb                   	sti
59b9     59b9:	f3 0f b8 c7          	popcnt %edi,%eax
59bd     59bd:	9c                   	pushf
59be     59be:	58                   	pop    %rax
59bf     59bf:	fa                   	cli
59c0     59c0:	9c                   	pushf
59c1     59c1:	58                   	pop    %rax
59c2     59c2:	fb                   	sti
59c3     59c3:	9c                   	pushf
59c4     59c4:	58                   	pop    %rax
59c5     59c5:	fa                   	cli
59c6     59c6:	fb                   	sti
59c7     59c7:	9c                   	pushf
59c8     59c8:	58                   	pop    %rax
59c9     59c9:	fa                   	cli
59ca     59ca:	fb                   	sti
59cb     59cb:	9c                   	pushf
59cc     59cc:	58                   	pop    %rax
59cd     59cd:	fa                   	cli
59ce     59ce:	fb                   	sti
59cf     59cf:	9c                   	pushf
59d0     59d0:	58                   	pop    %rax
59d1     59d1:	fa                   	cli
59d2     59d2:	9c                   	pushf
59d3     59d3:	58                   	pop    %rax
59d4     59d4:	fa                   	cli
59d5     59d5:	9c                   	pushf
59d6     59d6:	58                   	pop    %rax
59d7     59d7:	fb                   	sti
59d8     59d8:	9c                   	pushf
59d9     59d9:	58                   	pop    %rax
59da     59da:	fa                   	cli
59db     59db:	fb                   	sti
59dc     59dc:	9c                   	pushf
59dd     59dd:	58                   	pop    %rax
59de     59de:	fa                   	cli
59df     59df:	9c                   	pushf
59e0     59e0:	58                   	pop    %rax
59e1     59e1:	fa                   	cli
59e2     59e2:	9c                   	pushf
59e3     59e3:	58                   	pop    %rax
59e4     59e4:	fb                   	sti
59e5     59e5:	f3 0f b8 c7          	popcnt %edi,%eax
59e9     59e9:	9c                   	pushf
59ea     59ea:	58                   	pop    %rax
59eb     59eb:	fa                   	cli
59ec     59ec:	9c                   	pushf
59ed     59ed:	58                   	pop    %rax
59ee     59ee:	fb                   	sti
59ef     59ef:	0f 0d 08             	prefetchw (%rax)
59f2     59f2:	0f 0d 08             	prefetchw (%rax)
59f5     59f5:	9c                   	pushf
59f6     59f6:	58                   	pop    %rax
59f7     59f7:	fa                   	cli
59f8     59f8:	9c                   	pushf
59f9     59f9:	58                   	pop    %rax
59fa     59fa:	fb                   	sti
59fb     59fb:	9c                   	pushf
59fc     59fc:	58                   	pop    %rax
59fd     59fd:	fa                   	cli
59fe     59fe:	9c                   	pushf
59ff     59ff:	58                   	pop    %rax
5a00     5a00:	fb                   	sti
5a01     5a01:	9c                   	pushf
5a02     5a02:	58                   	pop    %rax
5a03     5a03:	fb                   	sti
5a04     5a04:	9c                   	pushf
5a05     5a05:	58                   	pop    %rax
5a06     5a06:	9c                   	pushf
5a07     5a07:	58                   	pop    %rax
5a08     5a08:	fa                   	cli
5a09     5a09:	9c                   	pushf
5a0a     5a0a:	58                   	pop    %rax
5a0b     5a0b:	fb                   	sti
5a0c     5a0c:	9c                   	pushf
5a0d     5a0d:	58                   	pop    %rax
5a0e     5a0e:	9c                   	pushf
5a0f     5a0f:	58                   	pop    %rax
5a10     5a10:	fa                   	cli
5a11     5a11:	0f 0d 08             	prefetchw (%rax)
5a14     5a14:	f3 0f b8 c7          	popcnt %edi,%eax
5a18     5a18:	9c                   	pushf
5a19     5a19:	58                   	pop    %rax
5a1a     5a1a:	fa                   	cli
5a1b     5a1b:	9c                   	pushf
5a1c     5a1c:	58                   	pop    %rax
5a1d     5a1d:	fb                   	sti
5a1e     5a1e:	f3 0f b8 c7          	popcnt %edi,%eax
5a22     5a22:	f3 0f b8 c7          	popcnt %edi,%eax
5a26     5a26:	f3 0f b8 c7          	popcnt %edi,%eax
5a2a     5a2a:	f3 48 0f b8 c7       	popcnt %rdi,%rax
5a2f     5a2f:	9c                   	pushf
5a30     5a30:	58                   	pop    %rax
5a31     5a31:	fa                   	cli
5a32     5a32:	9c                   	pushf
5a33     5a33:	58                   	pop    %rax
5a34     5a34:	fb                   	sti
5a35     5a35:	9c                   	pushf
5a36     5a36:	58                   	pop    %rax
5a37     5a37:	fa                   	cli
5a38     5a38:	9c                   	pushf
5a39     5a39:	58                   	pop    %rax
5a3a     5a3a:	fb                   	sti
5a3b     5a3b:	9c                   	pushf
5a3c     5a3c:	58                   	pop    %rax
5a3d     5a3d:	fa                   	cli
5a3e     5a3e:	9c                   	pushf
5a3f     5a3f:	58                   	pop    %rax
5a40     5a40:	fb                   	sti
5a41     5a41:	9c                   	pushf
5a42     5a42:	58                   	pop    %rax
5a43     5a43:	fa                   	cli
5a44     5a44:	9c                   	pushf
5a45     5a45:	58                   	pop    %rax
5a46     5a46:	fb                   	sti
5a47     5a47:	49 be 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%r14
5a51     5a51:	0f 01 cb             	stac
5a54     5a54:	e8 00 00 00 00       	call   5a59 <.altinstr_replacement+0x5a59>	5a55: R_X86_64_PLT32	clear_user_erms-0x4
5a59     5a59:	e8 00 00 00 00       	call   5a5e <.altinstr_replacement+0x5a5e>	5a5a: R_X86_64_PLT32	clear_user_rep_good-0x4
5a5e     5a5e:	e8 00 00 00 00       	call   5a63 <.altinstr_replacement+0x5a63>	5a5f: R_X86_64_PLT32	clear_user_original-0x4
5a63     5a63:	0f 01 ca             	clac
5a66     5a66:	f3 0f b8 c7          	popcnt %edi,%eax
5a6a     5a6a:	f3 0f b8 c7          	popcnt %edi,%eax
5a6e     5a6e:	f3 0f b8 c7          	popcnt %edi,%eax
5a72     5a72:	9c                   	pushf
5a73     5a73:	58                   	pop    %rax
5a74     5a74:	fa                   	cli
5a75     5a75:	9c                   	pushf
5a76     5a76:	58                   	pop    %rax
5a77     5a77:	fb                   	sti
5a78     5a78:	9c                   	pushf
5a79     5a79:	58                   	pop    %rax
5a7a     5a7a:	fa                   	cli
5a7b     5a7b:	9c                   	pushf
5a7c     5a7c:	58                   	pop    %rax
5a7d     5a7d:	fb                   	sti
5a7e     5a7e:	9c                   	pushf
5a7f     5a7f:	58                   	pop    %rax
5a80     5a80:	fa                   	cli
5a81     5a81:	9c                   	pushf
5a82     5a82:	58                   	pop    %rax
5a83     5a83:	fb                   	sti
5a84     5a84:	0f 0d 08             	prefetchw (%rax)
5a87     5a87:	9c                   	pushf
5a88     5a88:	58                   	pop    %rax
5a89     5a89:	fa                   	cli
5a8a     5a8a:	9c                   	pushf
5a8b     5a8b:	58                   	pop    %rax
5a8c     5a8c:	fb                   	sti
5a8d     5a8d:	9c                   	pushf
5a8e     5a8e:	58                   	pop    %rax
5a8f     5a8f:	fa                   	cli
5a90     5a90:	9c                   	pushf
5a91     5a91:	58                   	pop    %rax
5a92     5a92:	fb                   	sti
5a93     5a93:	9c                   	pushf
5a94     5a94:	58                   	pop    %rax
5a95     5a95:	fa                   	cli
5a96     5a96:	9c                   	pushf
5a97     5a97:	58                   	pop    %rax
5a98     5a98:	fb                   	sti
5a99     5a99:	9c                   	pushf
5a9a     5a9a:	58                   	pop    %rax
5a9b     5a9b:	fa                   	cli
5a9c     5a9c:	9c                   	pushf
5a9d     5a9d:	58                   	pop    %rax
5a9e     5a9e:	fb                   	sti
5a9f     5a9f:	9c                   	pushf
5aa0     5aa0:	58                   	pop    %rax
5aa1     5aa1:	fa                   	cli
5aa2     5aa2:	9c                   	pushf
5aa3     5aa3:	58                   	pop    %rax
5aa4     5aa4:	fb                   	sti
5aa5     5aa5:	9c                   	pushf
5aa6     5aa6:	58                   	pop    %rax
5aa7     5aa7:	fa                   	cli
5aa8     5aa8:	9c                   	pushf
5aa9     5aa9:	58                   	pop    %rax
5aaa     5aaa:	fb                   	sti
5aab     5aab:	f3 0f b8 c7          	popcnt %edi,%eax
5aaf     5aaf:	9c                   	pushf
5ab0     5ab0:	58                   	pop    %rax
5ab1     5ab1:	fa                   	cli
5ab2     5ab2:	9c                   	pushf
5ab3     5ab3:	58                   	pop    %rax
5ab4     5ab4:	fb                   	sti
5ab5     5ab5:	f3 0f b8 c7          	popcnt %edi,%eax
5ab9     5ab9:	f3 0f b8 c7          	popcnt %edi,%eax
5abd     5abd:	f3 0f b8 c7          	popcnt %edi,%eax
5ac1     5ac1:	f3 0f b8 c7          	popcnt %edi,%eax
5ac5     5ac5:	9c                   	pushf
5ac6     5ac6:	58                   	pop    %rax
5ac7     5ac7:	fa                   	cli
5ac8     5ac8:	9c                   	pushf
5ac9     5ac9:	58                   	pop    %rax
5aca     5aca:	fb                   	sti
5acb     5acb:	f3 0f b8 c7          	popcnt %edi,%eax
5acf     5acf:	f3 0f b8 c7          	popcnt %edi,%eax
5ad3     5ad3:	9c                   	pushf
5ad4     5ad4:	58                   	pop    %rax
5ad5     5ad5:	fa                   	cli
5ad6     5ad6:	9c                   	pushf
5ad7     5ad7:	58                   	pop    %rax
5ad8     5ad8:	fb                   	sti
5ad9     5ad9:	9c                   	pushf
5ada     5ada:	58                   	pop    %rax
5adb     5adb:	fa                   	cli
5adc     5adc:	9c                   	pushf
5add     5add:	58                   	pop    %rax
5ade     5ade:	fb                   	sti
5adf     5adf:	9c                   	pushf
5ae0     5ae0:	58                   	pop    %rax
5ae1     5ae1:	fa                   	cli
5ae2     5ae2:	9c                   	pushf
5ae3     5ae3:	58                   	pop    %rax
5ae4     5ae4:	fb                   	sti
5ae5     5ae5:	9c                   	pushf
5ae6     5ae6:	58                   	pop    %rax
5ae7     5ae7:	fa                   	cli
5ae8     5ae8:	9c                   	pushf
5ae9     5ae9:	58                   	pop    %rax
5aea     5aea:	fb                   	sti
5aeb     5aeb:	9c                   	pushf
5aec     5aec:	58                   	pop    %rax
5aed     5aed:	fa                   	cli
5aee     5aee:	9c                   	pushf
5aef     5aef:	58                   	pop    %rax
5af0     5af0:	fb                   	sti
5af1     5af1:	9c                   	pushf
5af2     5af2:	58                   	pop    %rax
5af3     5af3:	fa                   	cli
5af4     5af4:	9c                   	pushf
5af5     5af5:	58                   	pop    %rax
5af6     5af6:	fb                   	sti
5af7     5af7:	f3 0f b8 c7          	popcnt %edi,%eax
5afb     5afb:	f3 0f b8 c7          	popcnt %edi,%eax
5aff     5aff:	f3 0f b8 c7          	popcnt %edi,%eax
5b03     5b03:	9c                   	pushf
5b04     5b04:	58                   	pop    %rax
5b05     5b05:	fa                   	cli
5b06     5b06:	9c                   	pushf
5b07     5b07:	58                   	pop    %rax
5b08     5b08:	fb                   	sti
5b09     5b09:	f3 0f b8 c7          	popcnt %edi,%eax
5b0d     5b0d:	f3 0f b8 c7          	popcnt %edi,%eax
5b11     5b11:	9c                   	pushf
5b12     5b12:	58                   	pop    %rax
5b13     5b13:	9c                   	pushf
5b14     5b14:	58                   	pop    %rax
5b15     5b15:	9c                   	pushf
5b16     5b16:	58                   	pop    %rax
5b17     5b17:	fa                   	cli
5b18     5b18:	9c                   	pushf
5b19     5b19:	58                   	pop    %rax
5b1a     5b1a:	fb                   	sti
5b1b     5b1b:	9c                   	pushf
5b1c     5b1c:	58                   	pop    %rax
5b1d     5b1d:	fa                   	cli
5b1e     5b1e:	9c                   	pushf
5b1f     5b1f:	58                   	pop    %rax
5b20     5b20:	fb                   	sti
5b21     5b21:	f3 0f b8 c7          	popcnt %edi,%eax
5b25     5b25:	f3 0f b8 c7          	popcnt %edi,%eax
5b29     5b29:	9c                   	pushf
5b2a     5b2a:	58                   	pop    %rax
5b2b     5b2b:	9c                   	pushf
5b2c     5b2c:	58                   	pop    %rax
5b2d     5b2d:	fa                   	cli
5b2e     5b2e:	9c                   	pushf
5b2f     5b2f:	58                   	pop    %rax
5b30     5b30:	fb                   	sti
5b31     5b31:	48 bb 00 f0 ff ff ff ff ff 00 	movabs $0xfffffffffff000,%rbx
5b3b     5b3b:	9c                   	pushf
5b3c     5b3c:	58                   	pop    %rax
5b3d     5b3d:	fa                   	cli
5b3e     5b3e:	9c                   	pushf
5b3f     5b3f:	58                   	pop    %rax
5b40     5b40:	fb                   	sti
5b41     5b41:	9c                   	pushf
5b42     5b42:	58                   	pop    %rax
5b43     5b43:	9c                   	pushf
5b44     5b44:	58                   	pop    %rax
5b45     5b45:	fa                   	cli
5b46     5b46:	9c                   	pushf
5b47     5b47:	58                   	pop    %rax
5b48     5b48:	fb                   	sti
5b49     5b49:	9c                   	pushf
5b4a     5b4a:	58                   	pop    %rax
5b4b     5b4b:	fb                   	sti
5b4c     5b4c:	9c                   	pushf
5b4d     5b4d:	58                   	pop    %rax
5b4e     5b4e:	fa                   	cli
5b4f     5b4f:	9c                   	pushf
5b50     5b50:	58                   	pop    %rax
5b51     5b51:	fa                   	cli
5b52     5b52:	9c                   	pushf
5b53     5b53:	58                   	pop    %rax
5b54     5b54:	fb                   	sti
5b55     5b55:	9c                   	pushf
5b56     5b56:	58                   	pop    %rax
5b57     5b57:	f3 0f b8 c7          	popcnt %edi,%eax
5b5b     5b5b:	f3 0f b8 c7          	popcnt %edi,%eax
5b5f     5b5f:	f3 0f b8 c7          	popcnt %edi,%eax
5b63     5b63:	f3 0f b8 c7          	popcnt %edi,%eax
5b67     5b67:	f3 0f b8 c7          	popcnt %edi,%eax
5b6b     5b6b:	f3 0f b8 c7          	popcnt %edi,%eax
5b6f     5b6f:	f3 0f b8 c7          	popcnt %edi,%eax
5b73     5b73:	f3 0f b8 c7          	popcnt %edi,%eax
5b77     5b77:	f3 0f b8 c7          	popcnt %edi,%eax
5b7b     5b7b:	f3 0f b8 c7          	popcnt %edi,%eax
5b7f     5b7f:	f3 48 0f b8 c7       	popcnt %rdi,%rax
5b84     5b84:	f3 0f b8 c7          	popcnt %edi,%eax
5b88     5b88:	f3 0f b8 c7          	popcnt %edi,%eax
5b8c     5b8c:	f3 0f b8 c7          	popcnt %edi,%eax
5b90     5b90:	f3 0f b8 c7          	popcnt %edi,%eax
5b94     5b94:	f3 0f b8 c7          	popcnt %edi,%eax
5b98     5b98:	f3 0f b8 c7          	popcnt %edi,%eax
5b9c     5b9c:	f3 0f b8 c7          	popcnt %edi,%eax
5ba0     5ba0:	f3 0f b8 c7          	popcnt %edi,%eax
5ba4     5ba4:	f3 0f b8 c7          	popcnt %edi,%eax
5ba8     5ba8:	f3 0f b8 c7          	popcnt %edi,%eax
5bac     5bac:	f3 0f b8 c7          	popcnt %edi,%eax
5bb0     5bb0:	f3 0f b8 c7          	popcnt %edi,%eax
5bb4     5bb4:	f3 0f b8 c7          	popcnt %edi,%eax
5bb8     5bb8:	f3 0f b8 c7          	popcnt %edi,%eax
5bbc     5bbc:	f3 0f b8 c7          	popcnt %edi,%eax
5bc0     5bc0:	f3 0f b8 c7          	popcnt %edi,%eax
5bc4     5bc4:	f3 48 0f b8 c7       	popcnt %rdi,%rax
5bc9     5bc9:	f3 48 0f b8 c7       	popcnt %rdi,%rax
5bce     5bce:	f3 48 0f b8 c7       	popcnt %rdi,%rax
5bd3     5bd3:	f3 0f b8 c7          	popcnt %edi,%eax
5bd7     5bd7:	f3 48 0f b8 c7       	popcnt %rdi,%rax
5bdc     5bdc:	f3 48 0f b8 c7       	popcnt %rdi,%rax
5be1     5be1:	9c                   	pushf
5be2     5be2:	58                   	pop    %rax
5be3     5be3:	fa                   	cli
5be4     5be4:	9c                   	pushf
5be5     5be5:	58                   	pop    %rax
5be6     5be6:	fb                   	sti
5be7     5be7:	9c                   	pushf
5be8     5be8:	58                   	pop    %rax
5be9     5be9:	fa                   	cli
5bea     5bea:	9c                   	pushf
5beb     5beb:	58                   	pop    %rax
5bec     5bec:	fb                   	sti
5bed     5bed:	0f 20 d0             	mov    %cr2,%rax
5bf0     5bf0:	0f 20 d8             	mov    %cr3,%rax
5bf3     5bf3:	0f 22 df             	mov    %rdi,%cr3
5bf6     5bf6:	e9 00 00 00 00       	jmp    5bfb <.altinstr_replacement+0x5bfb>	5bf7: R_X86_64_PC32	.text+0xc8d6c8a
5bfb     5bfb:	48 89 f8             	mov    %rdi,%rax
5bfe     5bfe:	48 89 f8             	mov    %rdi,%rax
5c01     5c01:	48 89 f8             	mov    %rdi,%rax
5c04     5c04:	48 89 f8             	mov    %rdi,%rax
5c07     5c07:	e9 00 00 00 00       	jmp    5c0c <.altinstr_replacement+0x5c0c>	5c08: R_X86_64_PC32	.text+0xc8d6d8a
5c0c     5c0c:	48 89 f8             	mov    %rdi,%rax
5c0f     5c0f:	e9 00 00 00 00       	jmp    5c14 <.altinstr_replacement+0x5c14>	5c10: R_X86_64_PC32	.text+0xc8d6e21
5c14     5c14:	e9 00 00 00 00       	jmp    5c19 <.altinstr_replacement+0x5c19>	5c15: R_X86_64_PC32	.text+0xc8d821e
5c19     5c19:	48 89 f8             	mov    %rdi,%rax
5c1c     5c1c:	0f 20 d8             	mov    %cr3,%rax
5c1f     5c1f:	48 89 f8             	mov    %rdi,%rax
5c22     5c22:	48 89 f8             	mov    %rdi,%rax
5c25     5c25:	48 89 f8             	mov    %rdi,%rax
5c28     5c28:	48 89 f8             	mov    %rdi,%rax
5c2b     5c2b:	48 89 f8             	mov    %rdi,%rax
5c2e     5c2e:	48 89 f8             	mov    %rdi,%rax
5c31     5c31:	48 89 f8             	mov    %rdi,%rax
5c34     5c34:	48 89 f8             	mov    %rdi,%rax
5c37     5c37:	48 89 f8             	mov    %rdi,%rax
5c3a     5c3a:	48 89 f8             	mov    %rdi,%rax

-- 
0-DAY CI Kernel Test Service
https://01.org/lkp

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202209101749.RYRMIdqE-lkp%40intel.com.
