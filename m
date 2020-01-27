Return-Path: <kasan-dev+bncBC4LXIPCY4NRBS7FXXYQKGQEUYCNL7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33f.google.com (mail-ot1-x33f.google.com [IPv6:2607:f8b0:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 63EF414ACA0
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Jan 2020 00:31:25 +0100 (CET)
Received: by mail-ot1-x33f.google.com with SMTP id d16sf3543421otp.10
        for <lists+kasan-dev@lfdr.de>; Mon, 27 Jan 2020 15:31:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1580167884; cv=pass;
        d=google.com; s=arc-20160816;
        b=tkvhu5jqCNgo4GTcjmx9+9cfHvhugFwz7dvmLa3UrLy7TKrktS1WwjfxVPHDVEd1T5
         i02WwtIZBSitx3AJIZ6IZrFiRMiHQVhoaGOyMmXXP3HyPm29FVNqvqM55eR0nHe8otWc
         Msz8kUoTd+6Y6nr9nv5YhUHcCro8r8muYr+hAdk94LTXVPPeW0VruKjuEKSk+JyRiwYA
         1jKXG9T32VVS39RdXuErE5/rcuQNDmarZOwupJy3ZHzwnE+GXC/NCArt5Agxl5bL7JMW
         nqzkXh+J281JqsKOORJ+KGlVmOIUVWhT8cJ5KorcGt6kV9KENHftP7w7zfMDPyfn+20Y
         3FjA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=ZXlXmKkd28tXgXR3gJGqbo687wODBs/wgbpZFOCEeBc=;
        b=WrOUeR643VXCO0p0XLqZ0o1YFJMHuoufrJ7ic45Z5yfHhVMvBaPgAdhYeFXpLgC1a0
         V0GH8F6df+M/F5DS77c11VNIWoBjoB3Er9ILoZZPfgOBTYRHkibT3Zm963iR7OV3bh8r
         eIocDmideomXXq3j3kwzTmVIuWBCDQB6f0WWzeRAdTEKfNd7KHF2/MGKE1suN4PdA8C5
         nXBA7Unr/TR/MkkBhDPYKytiS0QD8ysjTOmgwyFNsWPne0hojeUVxLjGRRiLKTZTKzET
         XH5hIEjgJmeq8ksLIQnaiAZXoYIjJJTTAlapDzVwQr5un131cqffK/NK3MCnQf2kI0/l
         cJLQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of lkp@intel.com designates 134.134.136.31 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ZXlXmKkd28tXgXR3gJGqbo687wODBs/wgbpZFOCEeBc=;
        b=SXTfzQIlaXcp2bR74KFtreGeozsiZxqomeDjzx1joPjYzsmolMy/GLzbziFKdbhEny
         XqoB6nLqN0Yitzm4LiyJj3Im0jhsIq8fKnokJ53e2KzS7jtCbE5OUWGB12JQFuibWQO/
         QDvNxdl+qdiAGZxzWI8DU5ypnUiUZ+K9i1cMA8BbDF3lBOooE4lPn18FV9c1LD3ekC/d
         RpUXww/LZggNbnh/h6pUw5wmYN52TvsPsZnCAbOVbAH3FANYh2B1ZCOibHwzhHnAo1by
         95fHLVg82NLrvUe1ddW3Xajs1xTP45wcIEDLLuCdfu6jSPgCrJHgfPdKuB/pzW+t907J
         S5iA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ZXlXmKkd28tXgXR3gJGqbo687wODBs/wgbpZFOCEeBc=;
        b=saPLeRehs1Nlkuc2DuBxMuP4/YB0uqudQeLbw4tGJcagm1XB3Z/Hy6oNIlQcjf+mmf
         +CKOr6j1YDgSpjD/Hn6Sr0PQcpz9hi5XSJ26HwODUHp2pBCVt4ZKsiAc1ioqs/3Jt5jv
         0nC5mr9JGjDdKJXVfKuDsBtPzGaPECHXEWkEwXEeoUhOTmhlRPAUsmsrnfBrPIIxKBl/
         1+fzlvLvcl9n4dH/rzWWheZcIB5j9muHkfAfJ+V9u6AF6QdPFd8Xng5rVvNocWJo5J/T
         LTNvKTZPsMfFQUKOl0lotxCNmwBwzr72VnENRsK9YiXG46kl6s/dxX7i9f5Mq73NXMFO
         DCXA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVV/JUE0ZIDdWTiFCNiAVnXxGD6haBPHhLB+QgizV9RYojA5MOn
	6VZN1tJizka5Db1RTiAC2tk=
X-Google-Smtp-Source: APXvYqwu6UIR0q4sew7Qrr8/ObpPEfHoD4Vj8xLTmDujSXwUEm7rwG23vuoxqa1VaZH78rEJfGPHHA==
X-Received: by 2002:a9d:470:: with SMTP id 103mr14302318otc.217.1580167884056;
        Mon, 27 Jan 2020 15:31:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:c694:: with SMTP id w142ls1759655oif.6.gmail; Mon, 27
 Jan 2020 15:31:23 -0800 (PST)
X-Received: by 2002:a54:4595:: with SMTP id z21mr1098676oib.136.1580167883705;
        Mon, 27 Jan 2020 15:31:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1580167883; cv=none;
        d=google.com; s=arc-20160816;
        b=qa5vrBdzPCga0JlNe5rqsFwTig6glGf3P9iGuxlJZTSXkW6v3HsWl9Hv7KQ1PUd0Ox
         mY8JTtIp2nJaExCROQIUc4egtbsePkLe3Zc+NJ2WgzlS61WEWNPzLPwWVKkgR9xEbpdD
         ijQ2PY1jySQocMofiLBmjz6BQevw9eSukFD138/GgCFitNKPY1zS7ZV0LviQqxyDIkQi
         sza2BexyRPC1AfKCevcPgt9cZ9llyH6KAt92WOIgwLCOIjELgCVpFkBivhd2PrF5WXO7
         K+saoyRC/9f2pK0+FhP2FlF3eGmPntl2l3QTsvmxHy5yLVauVAzoaLfAKeRVYY94gfZh
         wwNg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=DLs3xZDfxOSty0ilAv3I7ITANwtCcrfHBTf00QlimKQ=;
        b=YItcWcJOv68I3NDDHaUH2fgn2/tm1BZbC87YnEknWSStzZaV5cT/+eWW7iB04Xk3kY
         xl6nmMtTMcd+EKMaFZhmXqLnNy07HdQKjNXUmd95JSc3j18YgrlLq/ykqfcw683zIFvF
         hfP5f8op0IPJK7YoyuIQe/0vx/EXHkTXA9PSc08OkXtWFBsV60l26232tXUheJcrpmRs
         xpD9srFNHkZcfoK3TnLbgc/Df/DvIZO2Pu3Z+3H3IcYkGRuTJtam7ZSVM97iXc5Uv0Af
         +X5dI++fL59619Nzmv3vX5BJ4R5OUW07NYs5Arm5liFbU4Ij5pewoZCZngNveJo0za6t
         Wumg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of lkp@intel.com designates 134.134.136.31 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga06.intel.com (mga06.intel.com. [134.134.136.31])
        by gmr-mx.google.com with ESMTPS id p5si535958oip.3.2020.01.27.15.31.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 27 Jan 2020 15:31:23 -0800 (PST)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 134.134.136.31 as permitted sender) client-ip=134.134.136.31;
X-Amp-Result: UNKNOWN
X-Amp-Original-Verdict: FILE UNKNOWN
X-Amp-File-Uploaded: False
Received: from orsmga001.jf.intel.com ([10.7.209.18])
  by orsmga104.jf.intel.com with ESMTP/TLS/DHE-RSA-AES256-GCM-SHA384; 27 Jan 2020 15:30:57 -0800
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="5.70,371,1574150400"; 
   d="scan'208";a="308922734"
Received: from lkp-server01.sh.intel.com (HELO lkp-server01) ([10.239.97.150])
  by orsmga001.jf.intel.com with ESMTP; 27 Jan 2020 15:30:55 -0800
Received: from kbuild by lkp-server01 with local (Exim 4.89)
	(envelope-from <lkp@intel.com>)
	id 1iwDqJ-0007LT-6q; Tue, 28 Jan 2020 07:30:55 +0800
Date: Tue, 28 Jan 2020 07:29:52 +0800
From: kbuild test robot <lkp@intel.com>
To: Qian Cai <cai@lca.pw>
Cc: kbuild-all@lists.01.org, ardb@kernel.org, mingo@redhat.com,
	kasan-dev@googlegroups.com, linux-efi@vger.kernel.org,
	linux-kernel@vger.kernel.org, Qian Cai <cai@lca.pw>
Subject: Re: [PATCH -next] x86/efi_64: fix a user-memory-access in runtime
Message-ID: <202001280700.tCtD1cvl%lkp@intel.com>
References: <20200118063022.21743-1-cai@lca.pw>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200118063022.21743-1-cai@lca.pw>
User-Agent: NeoMutt/20170113 (1.7.2)
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of lkp@intel.com designates 134.134.136.31 as permitted
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

Hi Qian,

Thank you for the patch! Perhaps something to improve:

[auto build test WARNING on next-20200117]
[cannot apply to efi/next v5.5]
[if your patch is applied to the wrong git tree, please drop us a note to help
improve the system. BTW, we also suggest to use '--base' option to specify the
base tree in git format-patch, please see https://stackoverflow.com/a/37406982]

url:    https://github.com/0day-ci/linux/commits/Qian-Cai/x86-efi_64-fix-a-user-memory-access-in-runtime/20200118-171142
base:    de970dffa7d19eae1d703c3534825308ef8d5dec
reproduce:
        # apt-get install sparse
        # sparse version: v0.6.1-153-g47b6dfef-dirty
        make ARCH=x86_64 allmodconfig
        make C=1 CF='-fdiagnostic-prefix -D__CHECK_ENDIAN__'

If you fix the issue, kindly add following tag
Reported-by: kbuild test robot <lkp@intel.com>


sparse warnings: (new ones prefixed by >>)

>> arch/x86/platform/efi/efi_64.c:1045:48: sparse: sparse: incorrect type in argument 2 (different address spaces)
>> arch/x86/platform/efi/efi_64.c:1045:48: sparse:    expected void const [noderef] <asn:1> *from
>> arch/x86/platform/efi/efi_64.c:1045:48: sparse:    got union efi_runtime_services_t [usertype] *[usertype] runtime

vim +1045 arch/x86/platform/efi/efi_64.c

  1020	
  1021	efi_status_t __init efi_set_virtual_address_map(unsigned long memory_map_size,
  1022							unsigned long descriptor_size,
  1023							u32 descriptor_version,
  1024							efi_memory_desc_t *virtual_map)
  1025	{
  1026		efi_runtime_services_t runtime;
  1027		efi_status_t status;
  1028		unsigned long flags;
  1029		pgd_t *save_pgd = NULL;
  1030	
  1031		if (efi_is_mixed())
  1032			return efi_thunk_set_virtual_address_map(memory_map_size,
  1033								 descriptor_size,
  1034								 descriptor_version,
  1035								 virtual_map);
  1036	
  1037		if (efi_enabled(EFI_OLD_MEMMAP)) {
  1038			save_pgd = efi_old_memmap_phys_prolog();
  1039			if (!save_pgd)
  1040				return EFI_ABORTED;
  1041		} else {
  1042			efi_switch_mm(&efi_mm);
  1043		}
  1044	
> 1045		if (copy_from_user(&runtime, efi.systab->runtime, sizeof(runtime)))

---
0-DAY kernel test infrastructure                 Open Source Technology Center
https://lists.01.org/hyperkitty/list/kbuild-all@lists.01.org Intel Corporation

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202001280700.tCtD1cvl%25lkp%40intel.com.
