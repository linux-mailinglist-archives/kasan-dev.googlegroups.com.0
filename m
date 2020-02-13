Return-Path: <kasan-dev+bncBDQ27FVWWUFRBP5ZSLZAKGQETKBZU3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd40.google.com (mail-io1-xd40.google.com [IPv6:2607:f8b0:4864:20::d40])
	by mail.lfdr.de (Postfix) with ESMTPS id 6FF3015B612
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Feb 2020 01:48:01 +0100 (CET)
Received: by mail-io1-xd40.google.com with SMTP id l62sf3045934ioa.19
        for <lists+kasan-dev@lfdr.de>; Wed, 12 Feb 2020 16:48:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581554880; cv=pass;
        d=google.com; s=arc-20160816;
        b=Gz/Clzu0BZT/YNT9hCdR+sdB8ZN27K6WSKaG7PjWnXLWE6JJ7l7drC7Tee1L47BvAW
         42fTRlddnS0Aib6iXQGBb8l/W8xFJrqwnNDI8nevjTfxTRSW/tDDWCW8NR8/7feQAU5O
         tw87gdmmAar29oyoxpqIbAG+UEQ3pA2wBEsba5htLnn8+eB3Oaw/u5NxiF39rrBBGcjZ
         +nL8aBE/AoiAB+VVTuXY8owZLJAtWy807pd6k6bpz5VTkz3oGZ8vaU8kP/avT7MKNoDO
         CfY05ksyr/q6oAXHl36Jpf9jy+RINoQbEED/bpv2NKLhdCbMR8w6fW7XwsKhJIezNQid
         GTIQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=SylQR9035OXFvNlRhgUCAAlGkql64MlmYlgQQTp6y8k=;
        b=hezWttA08+xYkI79ucQcu2ZaVd6NIEdlzhH9uu60tWsLen+lsESITrOG4hKb3RldXl
         ExkNFbjS6OzJik6IRor38/ILoQ2/Cj1Ahhwfj2e/AazlnsUdTgsfBROsuwnZuQM1czgt
         cLbRbbp1iKL/3sYZIPDg/8l+ja7p92SpxhlkYgk/NRz1qlA1M4fg5P64HPNqxxUnfHzL
         xo6iIkuZ5sVHJXK+bOYfxQl3AsPAE4NzP5E7/3Kw6ouVCnWRRfEmUhVAsNDGol/fPWtQ
         WGYdvYugk4E41tpD8sHlsS1EmOhH4ptOvAm5nVpmVduYoo3scWwGcC4xu+9Gaq6ibAZA
         Rt0A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=QwUP5Ymp;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::644 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SylQR9035OXFvNlRhgUCAAlGkql64MlmYlgQQTp6y8k=;
        b=aDd4I1OGakyedlCkpUYGLfpPkc8EnIAtJlbwquP2jzpezHhwC1lNtS5NTDBmyhtqSS
         d5/1Joe+sCASDEq6LjlBRbtLJcQCc1dLFRQ5jAM8aqNDX2ldVM/MKw5DzqwHOvtuwT7S
         qlDUUjM1hPwktm+WIu2fDSwIfGgRmJAsFYxj7vIuihOhb+IpSS8+2l7pv2/YU4n8/WU7
         sB1ispRnIng0Ut1IFVni5B9gia2Lb26EPLec/QkDhlY3O0rBrjnoYQMMV1PGzVYgQDUv
         dB1StuVRs4UVsyprQ/L0Jym0RAAYngJUs42q6bv3vIUD52lKMR2VD29ndVnBZuedYAbZ
         Nzlw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=SylQR9035OXFvNlRhgUCAAlGkql64MlmYlgQQTp6y8k=;
        b=XuLauOEJpkvBJkDer8hJaY6s2511z3gSF4LWTRXvcWfObbx/LQ/BUhIbpWetLyHVQo
         AOOtVrWy3icxWmohW4Jojd2hgbrI5efvUssAz/e6KJNi8suuYobrCE1VIY2epKymBJHD
         W0YHOKA7SZ+UAOR95yQV3mJ2+Ey4XL/q2jE4hZ6Xwt18CSb1J+XGzrYAfz+2K8CDc1Os
         Q/ciq9b4kDqi023/rgmiRAykfQ8kfhUgqdaZMbUrG2MD5k6U7LuYpY6nHTVw38eJjy9f
         79/i4kMXMROHS+vsQ4cjNKptXzOV7hKEtt9WKFy7OKh/9nj7syhQNfT1ZZSe7kdZOCnx
         CdIg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXcr8Kd+U8HyauUIOaXub8Xv16ZoLg91ArFS6B9Ugyuy5iYgeUT
	jB+3cs2pkyf4/309KqdXkH4=
X-Google-Smtp-Source: APXvYqwhjTDCuVZWIJ/3ayUZadoZNxfelhkudb1cNKCw0ysXlh7klBlOU+HfHScHjHbqzXSlD6MbqA==
X-Received: by 2002:a02:6a06:: with SMTP id l6mr21353907jac.111.1581554879932;
        Wed, 12 Feb 2020 16:47:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:8c10:: with SMTP id o16ls4198886ild.6.gmail; Wed, 12 Feb
 2020 16:47:59 -0800 (PST)
X-Received: by 2002:a92:c886:: with SMTP id w6mr13159071ilo.219.1581554879541;
        Wed, 12 Feb 2020 16:47:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581554879; cv=none;
        d=google.com; s=arc-20160816;
        b=Kr4MPpWl3ZUbEtg+QFVmIrZ3Dbvx311rce54JpAb1Akm95V2M7G6OrwwK2Z3ScDH+a
         gw2gzi5gOe3ikNTks8r7w/n0etZ/HdsYXDWE2wet+8AqLIew2ELzJF3GuKRFB85OuTjU
         UhICUAkW63Fv1tcSPeolV7dFPkvawHJEnLgmMC6vaU2teGLid9VFeYftNeEuy5WH8FYy
         txY3aS0aeRIr5TQULgDM9irJa1fOEEKwZf7w3/HVFlv+h3x0etqU8qVCrYj/PZ9rPuVW
         MsICdwE2tM/2ibzaCh/N9ksYtaIdjxo9EIKOsAnfDkrygLoVnf1t/VPTW9MWDafXkt2Z
         5wHA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=Jh/fY28bFcd7/L9cFsQkhcdCpmkjY9Ls0EJJsmxHbno=;
        b=fnsQFGyQxLdbe9EIjvAAmZqSQKnhBr+0qplMvluIZp67ThB+MmRB6FDJyviseYqXxy
         KZhLwJr6XnQv7XNllluj22QoAOv9vOT677pIaMCXtjbaqLcFlKWEpuu2l2zBgHIaxG66
         e1vBpTSkA+oU71he6NJCBaZi7FA5ZAyWLcBxqQE8sQXluZp/utue8/8KVsOnnaJmJm4N
         9YRlJKPMPuq0ZCMDvfIHgzmO86YE2ZuTzZAKD3QnCM2LZMZYLdo4wx/B36K/axS7TOl9
         db1u/iL71Fn/WpLunHfl1T3OgZ0Ir5QnmFg6a4TGzxLMz3oJr5S8/I2ePLxGhP/8etiZ
         nZig==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=QwUP5Ymp;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::644 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pl1-x644.google.com (mail-pl1-x644.google.com. [2607:f8b0:4864:20::644])
        by gmr-mx.google.com with ESMTPS id h4si52162ilf.3.2020.02.12.16.47.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 12 Feb 2020 16:47:59 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::644 as permitted sender) client-ip=2607:f8b0:4864:20::644;
Received: by mail-pl1-x644.google.com with SMTP id d9so1601329plo.11
        for <kasan-dev@googlegroups.com>; Wed, 12 Feb 2020 16:47:59 -0800 (PST)
X-Received: by 2002:a17:90a:858a:: with SMTP id m10mr1992942pjn.117.1581554878778;
        Wed, 12 Feb 2020 16:47:58 -0800 (PST)
Received: from localhost (2001-44b8-1113-6700-f1ea-0ab5-027b-8841.static.ipv6.internode.on.net. [2001:44b8:1113:6700:f1ea:ab5:27b:8841])
        by smtp.gmail.com with ESMTPSA id u126sm399077pfu.182.2020.02.12.16.47.57
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 12 Feb 2020 16:47:58 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	linuxppc-dev@lists.ozlabs.org,
	kasan-dev@googlegroups.com,
	christophe.leroy@c-s.fr,
	aneesh.kumar@linux.ibm.com,
	bsingharora@gmail.com
Cc: Daniel Axtens <dja@axtens.net>
Subject: [PATCH v7 0/4] KASAN for powerpc64 radix
Date: Thu, 13 Feb 2020 11:47:48 +1100
Message-Id: <20200213004752.11019-1-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=QwUP5Ymp;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::644 as
 permitted sender) smtp.mailfrom=dja@axtens.net
Content-Type: text/plain; charset="UTF-8"
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

Building on the work of Christophe, Aneesh and Balbir, I've ported
KASAN to 64-bit Book3S kernels running on the Radix MMU.

This provides full inline instrumentation on radix, but does require
that you be able to specify the amount of physically contiguous memory
on the system at compile time. More details in patch 4.

v7: Tweaks from Christophe, fix issues detected by snowpatch.

v6: Rebase on the latest changes in powerpc/merge. Minor tweaks
      to the documentation. Small tweaks to the header to work
      with the kasan_late_init() function that Christophe added
      for 32-bit kasan-vmalloc support.
    No functional change.

v5: ptdump support. More cleanups, tweaks and fixes, thanks
    Christophe. Details in patch 4.

    I have seen another stack walk splat, but I don't think it's
    related to the patch set, I think there's a bug somewhere else,
    probably in stack frame manipulation in the kernel or (more
    unlikely) in the compiler.

v4: More cleanups, split renaming out, clarify bits and bobs.
    Drop the stack walk disablement, that isn't needed. No other
    functional change.

v3: Reduce the overly ambitious scope of the MAX_PTRS change.
    Document more things, including around why some of the
    restrictions apply.
    Clean up the code more, thanks Christophe.

v2: The big change is the introduction of tree-wide(ish)
    MAX_PTRS_PER_{PTE,PMD,PUD} macros in preference to the previous
    approach, which was for the arch to override the page table array
    definitions with their own. (And I squashed the annoying
    intermittent crash!)

    Apart from that there's just a lot of cleanup. Christophe, I've
    addressed most of what you asked for and I will reply to your v1
    emails to clarify what remains unchanged.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200213004752.11019-1-dja%40axtens.net.
