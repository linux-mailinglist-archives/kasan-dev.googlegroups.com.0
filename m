Return-Path: <kasan-dev+bncBCLI747UVAFRBCHK2X2AKGQEOMYETWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33c.google.com (mail-ot1-x33c.google.com [IPv6:2607:f8b0:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 591D61A761F
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Apr 2020 10:32:09 +0200 (CEST)
Received: by mail-ot1-x33c.google.com with SMTP id k19sf9995363otl.8
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Apr 2020 01:32:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1586853128; cv=pass;
        d=google.com; s=arc-20160816;
        b=QytWhSo15wsfwvboXEwy2qquISzDCwp7ZcA63VzffgNABhkV0vQg1WxHDZE0yQfw34
         0rAFeQfeujtSiheO8B6RY6PUtewpin0dHY7kpXyNYnzWj+cNzdhjpeBB9++oqLkpbYYM
         EtpyVok959aUzB0I5kCkVxJBneG/pvVf5XjqWJxsEOsxuFOg0hmlTmtC/dyBpQv88TYX
         HzsAltz8fL8M1jMuHcz72JdTNnq4ZfdkuycWoNaEukxHtXbuwqqAKW7zNhsQlqoUhz79
         lrRN/kFkGmQ99N/A8TRqJ8vFzHhn3zIAqmxpQC/IdeE3L37Mk1W/DTZI2xRKpCSWcdBp
         HrAw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:date:message-id:from:references:cc:to:subject:sender
         :dkim-signature;
        bh=V2TkFMWvQAvWO++kxV9faffbeJoNct79jeohnjYvez4=;
        b=GaSijSTSw4/4VT5+I+HYFjhKQgj3dD9Ce9hEVsaWrcNUV8tCxxsCroKixzNWf6UZMP
         7WEd1E0/yieOX1scP7nEiXJi6+LLmmCw0FL3sn2ISdc83XBWeCjfSvaFqQnzPjnEc0sn
         zvoG4okTi9/jULgpaIBEbDrjaMzz+9vWWkY+bUlZvDU97oSz9WqnbZ5jmetJKxvu7pMf
         eOX1kEtjLVVwu/d6F4tgfElqYjazhy3qVYKUw9TPSGo78/IEp4UZNaDODkcrx5B5RLuA
         CtYQX9/rScP2SNKwYszEva1fHmIsNAMpAREOwoL/PmGAsn/zKrmx1Ih6ZU9DZGPxNfHS
         FUVg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=mail header.b=sx6IKJIx;
       spf=pass (google.com: domain of jason@zx2c4.com designates 192.95.5.64 as permitted sender) smtp.mailfrom=Jason@zx2c4.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=zx2c4.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:mime-version
         :in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=V2TkFMWvQAvWO++kxV9faffbeJoNct79jeohnjYvez4=;
        b=J5ktHI1m97PY7w99ipcU10yB72d227JT/9+tbRqZxFys75tJn30SBBhFDXd/cFj4qI
         zPgFtTR/+J8Hkwk2JbSoFp7E2mT9u43hMKetio3l4QL8ezS/1sIk3C7487c847PZotEn
         B4hmtBa5/qUMkiVw2G2qDqp3+97nigxdTZ2+swbrMm96ACaQ5f9Y2w4xf5C9JZmkB27N
         sN3yC0XuFm1kYE1GWvhq/wI1GUY4SuSpxwly5G45awiY8KJVPAxJJ0mSCp4Y/NQVX5Dk
         5FUVw11tJnhgm7fywsSSgVyBY1XE7K39H6dIqW9+XGYfiIv4S8saZZKdeCvisZIguHBe
         9EBw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=V2TkFMWvQAvWO++kxV9faffbeJoNct79jeohnjYvez4=;
        b=W3Ka9XMdmVCaDt502XmJD5pGDUsRZwlMvinTDMiHWcCcx7L+ZCaSm7gFZNdGHQJEqh
         WtwXAbxNr5J3dHW9rQPco/KIcHB5/qPjkN7p55NBuKq1n5/xkcAYEDVx42vsijk+k24Q
         5JWAU/gicj96U7P9EZ8voWnYBOuN8ZQDnjL8lKYBZSxw7j0fEp4eUu2l7KuyAhtW8uLe
         V8l0SBUdajWv/9Ki93CP4izjU17O9YGiwtxZM1au/XusCNtoi0S9oMLCHn5Ia1JuP4Ys
         KZXdq1DKa242iJa1kgAPmt9KNIkWm+jNFH179s5J6Tf5Q1/fGcJKl5PWPk3O5tCKP7dC
         gxWw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuYq3HgjEcMkFcbALbEorVg3sBJNZnIVymY5G3BqRnqNKHVEseJS
	Q+tqRfn6fNpte6vKBnvM1Rw=
X-Google-Smtp-Source: APiQypKbKi7/m75NtsUYFcVCs50qyBWBJ3yA+aAHgMRAWJvwghQAjSzVZH5PiCO0G43T+VSqbyH0SQ==
X-Received: by 2002:aca:5e0b:: with SMTP id s11mr13902664oib.111.1586853128321;
        Tue, 14 Apr 2020 01:32:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:3745:: with SMTP id r66ls152058oor.10.gmail; Tue, 14 Apr
 2020 01:32:08 -0700 (PDT)
X-Received: by 2002:a4a:55d8:: with SMTP id e207mr17554187oob.37.1586853127951;
        Tue, 14 Apr 2020 01:32:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1586853127; cv=none;
        d=google.com; s=arc-20160816;
        b=ZcS+29QUTBdGDgRpjZJ/RSUZGNmioXDBlIjO4c55Sb+Iywjl8H7QA0CqHhOQEUlrY0
         4DuCEb0BDX2JaTKYtm33HzQEHkFNjcdRaNMIqXr0MmIDK0dv/X2PK5rc5/hl5zrcvSKO
         4hyxVFhfWlbQQgTFmNrnmxfZb4qY9emYKzxhQNNoNUA4nk0oAJgdx0BJGZ0M6dDBarSr
         YMCgZVusjTTAUQGOQHBSGysv1qKZwcApVM7KY2Ydry4OFsFAvE8yfy7vlP3xrpuKTXHm
         rm8RmaJkulhTi7rI2tIXs97pTFk8Bati8XXQDeAsGabtzWyd9LY/rbZ3LU/Z2gW5GAAs
         hilQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :date:message-id:from:references:cc:to:subject:dkim-signature;
        bh=UKQsCwENnNIEAuJXvQ/tW8fkmNjG5WmayzQXfCLs/i4=;
        b=RdcJhV4DTuCJLOv6ZuZGLRYRAq6R5C2HcSRtbwnUF31kSsHaPuz6xqz0PqcKOAenOt
         l3sfn96f43e0KO2F3d4k3oAKVBoN9LTrSYwgKmekjVqw/GGoWOPhprDZE8kR17gylXAF
         bXCiouSb0SVbSy3vIwSO6jIvPQVW6OncCIk0za/78B8Io/aOBpNDpoe9u2M04Zp5SY62
         iFZbRPx6gApn6do2rNoRSXkQ2O7SXAhtc4xrn8mHiMu+oDYihQX6dxQk5yEuD0In28PQ
         SNkNhhgDMj4r3HUF0l/o1rk/OTVJ2l1v8WF5ox5SWM+9xZ20rbTFglBYa6RaZbYqAc5B
         GAsQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=mail header.b=sx6IKJIx;
       spf=pass (google.com: domain of jason@zx2c4.com designates 192.95.5.64 as permitted sender) smtp.mailfrom=Jason@zx2c4.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=zx2c4.com
Received: from mail.zx2c4.com (mail.zx2c4.com. [192.95.5.64])
        by gmr-mx.google.com with ESMTPS id m14si265235otn.5.2020.04.14.01.32.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 14 Apr 2020 01:32:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of jason@zx2c4.com designates 192.95.5.64 as permitted sender) client-ip=192.95.5.64;
Received: by mail.zx2c4.com (ZX2C4 Mail Server) with ESMTP id 9d220a78;
	Tue, 14 Apr 2020 08:22:18 +0000 (UTC)
Received: by mail.zx2c4.com (ZX2C4 Mail Server) with ESMTPSA id e4f42b92 (TLSv1.3:TLS_AES_256_GCM_SHA384:256:NO);
	Tue, 14 Apr 2020 08:22:18 +0000 (UTC)
Subject: Re: [PATCH 1/2] mm, treewide: Rename kzfree() to kfree_sensitive()
To: Waiman Long <longman@redhat.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 David Howells <dhowells@redhat.com>,
 Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>,
 James Morris <jmorris@namei.org>, "Serge E. Hallyn" <serge@hallyn.com>,
 Linus Torvalds <torvalds@linux-foundation.org>, Joe Perches
 <joe@perches.com>, Matthew Wilcox <willy@infradead.org>,
 David Rientjes <rientjes@google.com>
Cc: linux-mm@kvack.org, keyrings@vger.kernel.org,
 linux-kernel@vger.kernel.org, x86@kernel.org, linux-crypto@vger.kernel.org,
 linux-s390@vger.kernel.org, linux-pm@vger.kernel.org,
 linux-stm32@st-md-mailman.stormreply.com,
 linux-arm-kernel@lists.infradead.org, linux-amlogic@lists.infradead.org,
 linux-mediatek@lists.infradead.org, linuxppc-dev@lists.ozlabs.org,
 virtualization@lists.linux-foundation.org, netdev@vger.kernel.org,
 intel-wired-lan@lists.osuosl.org, linux-ppp@vger.kernel.org,
 wireguard@lists.zx2c4.com, linux-wireless@vger.kernel.org,
 devel@driverdev.osuosl.org, linux-scsi@vger.kernel.org,
 target-devel@vger.kernel.org, linux-btrfs@vger.kernel.org,
 linux-cifs@vger.kernel.org, samba-technical@lists.samba.org,
 linux-fscrypt@vger.kernel.org, ecryptfs@vger.kernel.org,
 kasan-dev@googlegroups.com, linux-bluetooth@vger.kernel.org,
 linux-wpan@vger.kernel.org, linux-sctp@vger.kernel.org,
 linux-nfs@vger.kernel.org, tipc-discussion@lists.sourceforge.net,
 cocci@systeme.lip6.fr, linux-security-module@vger.kernel.org,
 linux-integrity@vger.kernel.org
References: <20200413211550.8307-1-longman@redhat.com>
 <20200413211550.8307-2-longman@redhat.com>
From: "Jason A. Donenfeld" <Jason@zx2c4.com>
Message-ID: <4babf834-c531-50ba-53f6-e88410b15ce3@zx2c4.com>
Date: Tue, 14 Apr 2020 02:32:03 -0600
MIME-Version: 1.0
In-Reply-To: <20200413211550.8307-2-longman@redhat.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
X-Original-Sender: jason@zx2c4.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@zx2c4.com header.s=mail header.b=sx6IKJIx;       spf=pass
 (google.com: domain of jason@zx2c4.com designates 192.95.5.64 as permitted
 sender) smtp.mailfrom=Jason@zx2c4.com;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=zx2c4.com
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

On 4/13/20 3:15 PM, Waiman Long wrote:
> As said by Linus:
> 
>    A symmetric naming is only helpful if it implies symmetries in use.
>    Otherwise it's actively misleading.
> 
>    In "kzalloc()", the z is meaningful and an important part of what the
>    caller wants.
> 
>    In "kzfree()", the z is actively detrimental, because maybe in the
>    future we really _might_ want to use that "memfill(0xdeadbeef)" or
>    something. The "zero" part of the interface isn't even _relevant_.
> 
> The main reason that kzfree() exists is to clear sensitive information
> that should not be leaked to other future users of the same memory
> objects.
> 
> Rename kzfree() to kfree_sensitive() to follow the example of the
> recently added kvfree_sensitive() and make the intention of the API
> more explicit. 

Seems reasonable to me. One bikeshed, that you can safely discard and 
ignore as a mere bikeshed: kfree_memzero or kfree_scrub or 
kfree_{someverb} seems like a better function name, as it describes what 
the function does, rather than "_sensitive" that suggests something 
about the data maybe but who knows what that entails. If you disagree, 
not a big deal either way.

 > In addition, memzero_explicit() is used to clear the
 > memory to make sure that it won't get optimized away by the compiler.

This had occurred to me momentarily a number of years ago, but I was 
under the impression that the kernel presumes extern function calls to 
always imply a compiler barrier, making it difficult for the compiler to 
reason about what happens in/after kfree, in order to be able to 
optimize out the preceding memset. With LTO, that rule obviously 
changes. I guess new code should be written with cross-object 
optimizations in mind now a days? [Meanwhile, it would be sort of 
interesting to teach gcc about kfree to enable additional scary 
optimizations...]

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4babf834-c531-50ba-53f6-e88410b15ce3%40zx2c4.com.
