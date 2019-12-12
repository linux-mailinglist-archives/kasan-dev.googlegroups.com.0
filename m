Return-Path: <kasan-dev+bncBDQ27FVWWUFRB7UGZHXQKGQEMBCGCSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id B1B5F11CE91
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Dec 2019 14:41:20 +0100 (CET)
Received: by mail-pl1-x63f.google.com with SMTP id q19sf719008pll.13
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Dec 2019 05:41:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1576158079; cv=pass;
        d=google.com; s=arc-20160816;
        b=bD1v1/3MaQVcLrTTGIXBBHL7rMObA2knI03pKzGqMjyuCiYe6bax67tNPoOkULMKf3
         Wi76mMLIe/eDrYi+/gsEpK3w3+7TVAkZrl+L6KfShwqW8t1kmL2WDhzPKiDK6/8ANM0N
         VC9KN45F+/3rNTzu3fIvVqb4AhgKayGacXNruzaO0TP6U0pWYdU20FtfiSXMBSaQdb8R
         Dbq70LTC7za05N+a0xtKy2StvrcBR2QGCCohYdQU0dANvWc7ctxOzZKBxjUJNNlAkqEt
         SdTvgaR2DiyLQvXVjEk9rC4PrmGeeF+NR51ikpBk8Qo78Yzw0YdiwT96Gl/8NEa7j0nu
         aR3Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:to:from:sender:dkim-signature;
        bh=5sQZnaVGV2ZoFJGTaQdGqZmwLs94mbma64pQfsaXaLE=;
        b=tRI73KAlIbHVwhZPOaR3uV5igz/ikk6JJBxogE+nnhqhSkdK9CioVI6YuLLTrTC9/r
         p7ceQukuvu3DKMOoRpp0Kes3nyk+U+GaU2bso4it/9Up7auBumiL4g/oAWmviWwlaKdP
         V4cxhBdRmbbmVNdRfoaVIIMsCeuZp5MOmTgnM9aJCVrr7Q1Kkv3DUGueaX42kCMHoaDf
         z2snoQYaIHEyhDS2Dd08EQrrDNb8Hvi0jQzAD97hFgb7k10Wn3hjL1upHD3NoS1iGfrf
         mbrQz6Zn9o1eR5knLgDGfGb4qHRoCZDIWY04/hY9xQ9jPspX6s4VLg7XEomvQfHNuy8b
         4LGA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=GdElbodE;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1042 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5sQZnaVGV2ZoFJGTaQdGqZmwLs94mbma64pQfsaXaLE=;
        b=n4+Wffc1LQmcPmmhijYK4uZ6YfNZzF74ir0Dyox396S5B6stMGdynyyEITUe6O2fqQ
         Cc8yIgUSTod9SOmr1wDoSqZDv41HjfyTTPlU8wJH+5UMralGG/QjCwtYO2BEyDBHt6+b
         g4iVNMuWYt+uSDd/OHgVTnNsoq8ZM2PIo6H2uBk6+9vUba3td15iXLk4pnnh5AJy+vFh
         5blzhsgUS7Ppd1mGQoSxVbQ0jpTtedWzS1TCPU5AdOhwQAlFLOLiRSzU19wFTjEvBpEN
         r0shrTNoQt0h3XfePtdfgAm4VsGKxjZR5396UR/lqMcL7+95A2zamvLIKORLBOS6p4bP
         H7Bw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5sQZnaVGV2ZoFJGTaQdGqZmwLs94mbma64pQfsaXaLE=;
        b=JGh41ir9enyNHZqM0sWvakmMQe4786u5qUGSABJd+G/QoFxCuonHcWF1MUT484mfBl
         fGseknecp256GEUYywae0zv8YNczKC1blXgkixpe972F3GmsXZ6d0EBFK7EsNNcC9oQG
         geNmY7YCswvgYegsjfSp3GlrGbxOZjjQwjOHcFL9kiTOtba/0NaH3YakQRUrfd1hm4yz
         Pv60ThEKQ6ePld8m/LSf3h9DhRWW2PamhE50tOzuc73O+F3CzoRGOuwrfTzZoLHc8+FT
         bFIugqZjC1t9QFxfjF0yhUEqlMtfBgigJmd752ZxrsrBX5ToLd07h+egOkAGPr90fVJM
         PiQQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUtb7tZSE3y/TM9CrjlEEkwBuI1GNVS3nGZvIN3IZHtvrR4i4mt
	lPUzZxFiKZlW/PoWPAEaloY=
X-Google-Smtp-Source: APXvYqyrYgj+NES/NyyPAlRqiHIFaQtOhWg3mddjyxnM3x3d2JjyXWw3Wet5ftKycFzn4c5HukRiBA==
X-Received: by 2002:a17:902:8e83:: with SMTP id bg3mr9894954plb.30.1576158079052;
        Thu, 12 Dec 2019 05:41:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:7293:: with SMTP id d19ls1447322pll.13.gmail; Thu,
 12 Dec 2019 05:41:18 -0800 (PST)
X-Received: by 2002:a17:90a:e28e:: with SMTP id d14mr10306412pjz.56.1576158078677;
        Thu, 12 Dec 2019 05:41:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1576158078; cv=none;
        d=google.com; s=arc-20160816;
        b=i9HUJTNMyoNt/21q4qCgCwDt9g2smW5SY8fZfvxwOkrF2QjGnc9NcmetoFzBlpHPbE
         +0VEPwLQ8lqKbs4v6NS1ZxFzphYN6vetvZKN5tjn6anzvjoItBNpfO7WzCc/JG1Rk4DO
         YgMI4oHFnpW69uFTMet8eZq8C5S9pRQeryBgQ01BlvkjqNQFZGorDE1qhCxVLZNlJ7fQ
         Rl6dl0dmmvsUy47j0f7Eom5Qo85kSk1qvU3UGnUXSZ9CJf+gDE5qUMW+OZf22rWECtyV
         B+lwcWokxSI8Ss5viAbwTXJcL1xx5lXTYpfjXKMe28cNGdsj/H+L+f7Ivwmc0x/DgPWH
         h4AA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:to:from
         :dkim-signature;
        bh=K1dcdOatOeVeFsIQxT5aEB0ANkvhzz2V9qjht9zfLUs=;
        b=hEzT4/BU2EXxI7KPedlSNa80t1KSK7YNX0Fvt1bwMaqqy+W/an7wNGMni0FmOPjkc6
         Vz2x0IjLxfS3FIt98P+TU7KX6cxOSE2Ip+B9STJMG3PS8Xy+xA1buVovyxMPedWlZPaQ
         Lv1nbgeeoKMWsVVAAVAse3mVG/Zxy6PatmF5gTwD3SrEabV1UKPJxyRBWXQBvGhP7DdK
         veqVD3OI500RI6qYzwChpbcwcz7/EQ3nmaf6DXHdBY335pMtH9xf7gQPlqMy/wuwNuAh
         UgdN4tQ8TwAoZtXV5CQbzG2BdtT+eONHLzPWBhnCNkSQ7hAbKx0j22xoY7PqIoUjrSTP
         mQ3A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=GdElbodE;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1042 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pj1-x1042.google.com (mail-pj1-x1042.google.com. [2607:f8b0:4864:20::1042])
        by gmr-mx.google.com with ESMTPS id cu4si150648pjb.1.2019.12.12.05.41.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 12 Dec 2019 05:41:18 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1042 as permitted sender) client-ip=2607:f8b0:4864:20::1042;
Received: by mail-pj1-x1042.google.com with SMTP id z21so1043650pjq.13
        for <kasan-dev@googlegroups.com>; Thu, 12 Dec 2019 05:41:18 -0800 (PST)
X-Received: by 2002:a17:902:9885:: with SMTP id s5mr9457771plp.217.1576158078207;
        Thu, 12 Dec 2019 05:41:18 -0800 (PST)
Received: from localhost (2001-44b8-1113-6700-b116-2689-a4a9-76f8.static.ipv6.internode.on.net. [2001:44b8:1113:6700:b116:2689:a4a9:76f8])
        by smtp.gmail.com with ESMTPSA id i68sm7464966pfe.173.2019.12.12.05.41.16
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 12 Dec 2019 05:41:17 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: Christophe Leroy <christophe.leroy@c-s.fr>, linux-kernel@vger.kernel.org, linux-mm@kvack.org, linuxppc-dev@lists.ozlabs.org, linux-s390@vger.kernel.org, linux-xtensa@linux-xtensa.org, linux-arch@vger.kernel.org, linux-arm-kernel@lists.infradead.org, kasan-dev@googlegroups.com, aneesh.kumar@linux.ibm.com, bsingharora@gmail.com
Subject: Re: [PATCH v2 4/4] powerpc: Book3S 64-bit "heavyweight" KASAN support
In-Reply-To: <414293e0-3b75-8e78-90d8-2c14182f3739@c-s.fr>
References: <20191210044714.27265-1-dja@axtens.net> <20191210044714.27265-5-dja@axtens.net> <414293e0-3b75-8e78-90d8-2c14182f3739@c-s.fr>
Date: Fri, 13 Dec 2019 00:41:14 +1100
Message-ID: <87tv65br0l.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=GdElbodE;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1042 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

Hi Christophe,

I think I've covered everything you've mentioned in the v3 I'm about to
send, except for:

>> +	/* mark early shadow region as RO and wipe */
>> +	pte = __pte(__pa(kasan_early_shadow_page) |
>> +		    pgprot_val(PAGE_KERNEL_RO) | _PAGE_PTE);
>
> Any reason for _PAGE_PTE being required here and not being included in 
> PAGE_KERNEL_RO ?

I'm not 100% sure quite what you mean here. I think you're asking: why
do we need to supply _PAGE_PTE here, shouldn't PAGE_KERNEL_RO set that
bit or cover that case?

_PAGE_PTE is defined by section 5.7.10.2 of Book III of ISA 3.0: bit 1
(linux bit 62) is 'Leaf (entry is a PTE)' I originally had this because
it was set in Balbir's original implementation, but the bit is also set
by pte_mkpte which is called in set_pte_at, so I also think it's right
to set it.

I don't know why it's not included in the permission classes; I suspect
it's because it's not conceptually a permission, it's set and cleared in
things like swp entry code.

Does that answer your question?

Regards,
Daniel

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87tv65br0l.fsf%40dja-thinkpad.axtens.net.
