Return-Path: <kasan-dev+bncBC5ZR244WYFRBJFAYSZQMGQEGONFMPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc37.google.com (mail-oo1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id 1AAD690C2E9
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Jun 2024 06:42:14 +0200 (CEST)
Received: by mail-oo1-xc37.google.com with SMTP id 006d021491bc7-5babff5b1easf5111892eaf.1
        for <lists+kasan-dev@lfdr.de>; Mon, 17 Jun 2024 21:42:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718685732; cv=pass;
        d=google.com; s=arc-20160816;
        b=fGVx2jgZ+OCdS+bmQxRAfO2N1E3jPHEKDcTAJzTy++vZXwB0wzfnMGCu+AodDBzjbE
         Hzgl+c/gm8+0n3rvUIm9vhzQVog9KIsZd/8kMBm6KeqpXBQaAyzj8fCS/tlmqMRyWn/U
         Aej8fkCsW298pk3YKjFlzU0ZSFICjNdjGANwlW13V7Q4toNmglwPoFx/QQQVhIBvAvbW
         wu6embR3Aft+nwYWNO8oU6vXIs0+WEhwt+cucEyY36snkepFjlQQf8/FEClR4NV/ulEW
         atLrIZBXZoTDn22t3s7rrBkCft3hysmrFYxc2pV5PWwgwZ70H9I4/DMaOlGouOBYMYyp
         YeKA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-disposition:mime-version
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=sPgJcLIoItA+jzIOmfHgCcw9RyuiMpAYxzIfuHgX1yk=;
        fh=VpvP35it6gvsecOnwOwbwfFKQdnWAzFaLQ5bBdo+mDk=;
        b=yZNIzQji3DtJlbbng+mZUFX5UcKn8BCK0/WVAMhylnvOHV4Y8EpxQ9XCBorff1Syib
         nQf2BZsXWSpGzWdcAPCUqwTK17KhWDmE8g39aEIGWH4HV0BkdF3HNkMJL8tseZ5NuS8y
         2eW44zxss9NIFAcpj/ASyUD5vMCuqAH9kQfS5FNuX4goxenBDr5UmdG9/N6LXaZV/1aw
         AB4a4aF2VEejpTy4TDPP4Tl76xAxe38q5eC7OCNk3yzWhI8SZ04ysIvmKPDUywB3CBjs
         k9DRS+IuLSEB2VQTedBMzgkmabmY2or5c9XppD4AZTlnEbC17V/NZm+PSTl3RMb3eVGL
         we7Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=YLGFbLm4;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=kirill.shutemov@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718685732; x=1719290532; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-disposition:mime-version:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=sPgJcLIoItA+jzIOmfHgCcw9RyuiMpAYxzIfuHgX1yk=;
        b=rJE6zZo8TWXPC465x/Ji4sELel5btwLKB4OZCC+0Xgvv+aX79XMhDjU9PdH47YBmd8
         XkzI5bMqcpG8NOSp4BoFts3yX9xjZyQL2/gJii1HgTSuAiKT48jFnxrNim2BEy/Klt33
         naS64oc6HwH2EetHnfsph+PtdumzckasN1gDTTokmNSKbheoNdhaFMV/Z/SdOPXZKbBR
         cMDnM5ZfrFlxmB7YKvR5V2gC30/8PZCkPuegeyBtq0eRfwp8CXw5CXRsZdQFORY5juxf
         yy6xDfydnkMZreH9yjljf2vtH9dgR2MzODiAYg7sv0zkgZtEFVd9cTxZ4C8bZ17vAEC7
         z0ww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718685732; x=1719290532;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-disposition:mime-version:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=sPgJcLIoItA+jzIOmfHgCcw9RyuiMpAYxzIfuHgX1yk=;
        b=BZHl8L0BU+4Yrh7Dcl20bazFgubIrZnrNwF76mci+enDd907UBsa8DbWKnv4GGpAAO
         Dg2bKlFvdxn/yTGkYzvKlu49Xsgj6OZhB2XtMrzi8Y/4M2h6HqvkGL+ee/Ip/Dkx8p2+
         mCTx5rgDZimGx4MjWFkh6vFr8V/hth48SJzmPq0F+39pF57pcs7TTuV2vyvPiwlHA9fS
         FjJGhI6yN3jAbp5iX2PqcBC82qFlM9jRr4i9n2Bzoag//QDfbLo8XZF6Df1oVIfAy92o
         6R7NTEf+pmLlyXald1wbDtg1Ru/CVxbOLF5x8tT/RWe66K81/dp8hAWer5k9BpKMbvzk
         OEtA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUpCPttixGy80VsmUDAFPvKvG557il0Kf80NPRONazLyoiqKHqLE2FsXIO35OOZBeUn92E72/20Q3kdnGdhCny6zRq08Wf34Q==
X-Gm-Message-State: AOJu0YwrnO5vrUNHrNqnnayTAXqOzU28iZwmWr6GyOU1yToMsPmoCJhT
	t8hCk1SBfdNq+s6y0BrGMQjNoAnGU1451W83YUJvp3iFJa4ZsqyW
X-Google-Smtp-Source: AGHT+IFWpSDkOoR2F5bqgmbNtwsLXtwEoTA1XpF2+IOqeeiaU5NsRz6pzDRohf9VAWQ6Ug0WX1EyTw==
X-Received: by 2002:a05:6870:304f:b0:254:ae7b:28ab with SMTP id 586e51a60fabf-25972ddc260mr792355fac.13.1718685732134;
        Mon, 17 Jun 2024 21:42:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:d286:b0:24f:f6d5:2d15 with SMTP id
 586e51a60fabf-2552b686017ls1580337fac.0.-pod-prod-00-us; Mon, 17 Jun 2024
 21:42:11 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXB5E42edScwOjSiJkuraYhqF4kzC6MSi7xvUuctqAT1K8rW+5JYqLdorYqaqk9tyqP824qnWBWO+l+JGRLt0Zuewb+QMt3hrlIsw==
X-Received: by 2002:a05:6808:f91:b0:3d2:177d:aa95 with SMTP id 5614622812f47-3d50efd815dmr668139b6e.5.1718685730996;
        Mon, 17 Jun 2024 21:42:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718685730; cv=none;
        d=google.com; s=arc-20160816;
        b=f2DzorMNMvAGefv1vNZHBR5uMeLgHbiuJO/GSusKstkSBnKCz0tIZUfl5qjR9nOnz+
         OIPNAd39sJdvDTl6gl3ia8G2VO0GIZw5d+iRHzhBIVf9LdhkGmXjhgFv4JgA/7eFM7ie
         KjpiFkSOrtALUCCUIwKDLOr3YTAah7yHSNRrbryQ7XLRKs2dWdO4K84QWfNxTNr8BxUu
         TnGV+wb/IpztRbXlNnMZspgjJ1dC3fuy/6zQwPTCOuAYiVzTXka9wuzdD1+q8QHSFsvR
         6P6ldB8AJYyGsqkjBPdrSuEwjqzIZqDlL1+/403oi89hEkC+mpy+SdVlJY2E0CORxvhh
         9PMQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-disposition:mime-version:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=RWAOakSa72hJIapiOfchoKwYYY0qvHSbnuDPWaKnCPk=;
        fh=S74PoC20emYV2U7pgcMtuOUpclbPP5WbV7Aig2QVomE=;
        b=aUbnQe8bnYVYMTqEvyAf7arUbmDCNBeb175BaOhyuW179MXUedDXW8ToOKY2/f4mEL
         lZ9gBNGaJcAEFNcf+vFAyhKoCm6zzcJpsITnU6NH+ABXUSBHKoJqCQkQ0VdroBWBWR2j
         2par9YPW4EFZZ9d6p7TMod7gkx13tabWL5PqJDDGkXePo6NjYq+aZ8rjJwYXl1Q7/YqG
         bvhjAQH3XNzPxnpAc44Hoi3XaEVJdWSxfYKHqG2twQYUHswQzIHCh/ydWZb4wQ1CDbY+
         8R8ZXj/+5ILuIe8frQQwfEEVKFi08EDgC2aSIqeqe2HG+StMgWBgav+9UUtk688Rj5B/
         fL6A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=YLGFbLm4;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=kirill.shutemov@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.21])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-3d2479698b2si462341b6e.1.2024.06.17.21.42.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 17 Jun 2024 21:42:10 -0700 (PDT)
Received-SPF: none (google.com: linux.intel.com does not designate permitted sender hosts) client-ip=198.175.65.21;
X-CSE-ConnectionGUID: xExSMJyITnWalg5rculZCg==
X-CSE-MsgGUID: YgWFnp+wRWiSsl2iaqNgsg==
X-IronPort-AV: E=McAfee;i="6700,10204,11106"; a="15506258"
X-IronPort-AV: E=Sophos;i="6.08,246,1712646000"; 
   d="scan'208";a="15506258"
Received: from fmviesa004.fm.intel.com ([10.60.135.144])
  by orvoesa113.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 17 Jun 2024 21:42:09 -0700
X-CSE-ConnectionGUID: bvILXEQXRZKrUsz9Qhjy/w==
X-CSE-MsgGUID: nRr+Pw4RQzKpL6599FwWKg==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.08,246,1712646000"; 
   d="scan'208";a="45954220"
Received: from black.fi.intel.com ([10.237.72.28])
  by fmviesa004.fm.intel.com with ESMTP; 17 Jun 2024 21:42:09 -0700
Received: by black.fi.intel.com (Postfix, from userid 1000)
	id 862781CB; Tue, 18 Jun 2024 07:42:06 +0300 (EEST)
Date: Tue, 18 Jun 2024 07:42:06 +0300
From: "Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>
To: Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com
Cc: x86@kernel.org, Dave Hansen <dave.hansen@linux.intel.com>
Subject: KMSAN stability
Message-ID: <dgsgqssodokkzy6e7xreydep27ct2uldnc6eypmz3rwly6u6yq@3udi3sbubg7a>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
X-Original-Sender: kirill.shutemov@linux.intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=YLGFbLm4;       spf=none
 (google.com: linux.intel.com does not designate permitted sender hosts)
 smtp.mailfrom=kirill.shutemov@linux.intel.com;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=intel.com
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

Hi,

I attempted to use KMSAN, but I had difficulty getting the system to boot
with the feature enabled.

The kernel boots successfully in my x86-64 VM if I enable KMSAN on top of
defconfig. However, if I try to enable *any* of the following options, the
boot stops:

- CONFIG_DEBUG_VIRTUAL
- CONFIG_DEBUG_LOCK_ALLOC
- CONFIG_DEFERRED_STRUCT_PAGE_INIT

The kernel becomes stuck just after KMSAN is initialized. I do not
understand the internals of KMSAN and I do not see an obvious reason for
this failure.

I have a feeling that the list of problematic options is not exhaustive.

Any ideas?

I also noticed an instrumentation issue:

vmlinux.o: warning: objtool: handle_bug+0x4: call to kmsan_unpoison_entry_regs() leaves .noinstr.text section

-- 
  Kiryl Shutsemau / Kirill A. Shutemov

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/dgsgqssodokkzy6e7xreydep27ct2uldnc6eypmz3rwly6u6yq%403udi3sbubg7a.
