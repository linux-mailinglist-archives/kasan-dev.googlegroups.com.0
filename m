Return-Path: <kasan-dev+bncBCM2HQW3QYHRB3HMUT3QKGQEQU6CKGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3e.google.com (mail-yb1-xb3e.google.com [IPv6:2607:f8b0:4864:20::b3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 78CEA1FC0C2
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Jun 2020 23:15:25 +0200 (CEST)
Received: by mail-yb1-xb3e.google.com with SMTP id s90sf62616ybi.6
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Jun 2020 14:15:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592342124; cv=pass;
        d=google.com; s=arc-20160816;
        b=lNspV01QBeqj6CI+tt2jQFJir2JMY8wRg3XQeSwxN4LfSpNoohGn9MQ4l3Zq5vp0fN
         NMSiDlf1QpmaXs1oca8Xzsc+M0TfnK4dcqLkoU/qvSpeunduGbHtbgTpprA5R/uEzEse
         RNn0Ns1ZvsP52odDO/JMGESRnjMDotm1/gDwtAcqGYH9a2oHUvo25+qANIET7kUgKceU
         2tM0PcH4qrXRqcb8Xueu4Yz4Is6adgWmUTi6VfIQ5xWT4s1xZvoXdVR93m8Y5GC7xGVN
         9ViKb3KUf2tePnFLZheLsOwTJta5Wx62kZ/7ZUwUwsvETt+h4qE8TVvAPBxwtOQDd2sL
         TMrA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=mpoQKW3kpJP5ZyoPymmcMDpumLAlARij/KTuFSZdDPQ=;
        b=rPbYmF/zWIxALuNG/jdP77FOoKMtWwhya3f33PL1XKvzh+7SA9ZPYrtckLeQkbubk1
         RbvzkT7E+RncaG2J48aC4unH+XI0wEBxoF6g3WAbpacx9/Bg01Oc1dQ+9COsZn3jVAXT
         9tKhPUoArdulWz67ZbnluS7Acj9IcyebV4TrZ0OP2jq6BFzlFHt+e3Ud5HyZE3JFBZhA
         5N1QpzKl9lY0b7wiLkiUZurSUX+av491P18J3GEmbINs64C14mMQNUGTV9L5TPlJV5fp
         Gc6KCT8AuotGUhnE29CikWECYnrULEyI41tNgvknv0/d4RQVDYmb3wDT6IjORrfNhUev
         kDlA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b="oHgSA/KC";
       spf=pass (google.com: best guess record for domain of willy@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=willy@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=mpoQKW3kpJP5ZyoPymmcMDpumLAlARij/KTuFSZdDPQ=;
        b=Z2IWxO6Uc8L8Gi1Bi8wDA+VGd98h3kav6twe4AGXnmqY8L528xHIX6zFa/Sw8h9KEz
         oEeImpPAhbWfdoTktkZdTAEDr7LlerPn8JcDd+kA0hpQBML1MFlgmAkDmZ09zrWFWxAe
         U30pSU3gix4NhVxXLS/XT25cKnBmH5Gpx6b7hRr2GrjjRlgnW/KFeFvHDhRkB+AiJ22y
         7P4qhHqrAy/60wQ4kmJmlEI57JBGPFOzwYkEZsQgQXPxddmEHSo5onrBFrGkWFaG3jNC
         DoNMFiQndKEK9snNBgs2+D0zutgKGT0JGcDF9RTBbRsG/l4Y3jy3A4KJzC9byzg+j2ol
         OGKg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=mpoQKW3kpJP5ZyoPymmcMDpumLAlARij/KTuFSZdDPQ=;
        b=KsqTKyfUC7/Yd7Lfy708y4yoLzi0m5Pzm8Y4AaOznQxLyugGeuPtZOXb7rYWJlQdwG
         3DLa8549ri8jTRXd2XBQm/RrfLxcbtT+gy4amEUKJuvS7V/NHdR3OriBWdl9pCFxXBiT
         HT4y+BRIjjCKq1BSgFucAbKhz7GaI7PcoqXjV3+UQlYgn+a/phmsgUfjS+QDGrpxbOAY
         0gaKSwFudEhRO3KvebKjdoy0C9CmSYQF5NjgMoCEelMzy1fkGJu6r2pMbIc5an8UGZKm
         1r4BgKPQ5u0PcVj8j40Y2tTj6mPoE0uGS2843B2r6m8aDXo2LBhmCFPaChE+7tY6NgzH
         2kZw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531PGYPgc67e93vT41pYnkWpS9DbtVVah/QJmEsBqQdEkGP3dY4R
	sHNAk7vCVdC3ZLknpp7vqh0=
X-Google-Smtp-Source: ABdhPJySyQd70jI/PBywDlextz4Aiqqot1muhiEDfcSxF2peBxne1P5zd0gZaSTlh58Bjnj44vifOg==
X-Received: by 2002:a25:2d57:: with SMTP id s23mr8221085ybe.11.1592342124505;
        Tue, 16 Jun 2020 14:15:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:6602:: with SMTP id a2ls82239ybc.0.gmail; Tue, 16 Jun
 2020 14:15:24 -0700 (PDT)
X-Received: by 2002:a25:dd42:: with SMTP id u63mr8189263ybg.269.1592342124162;
        Tue, 16 Jun 2020 14:15:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592342124; cv=none;
        d=google.com; s=arc-20160816;
        b=zl5bk9/Z0tpg5AZvBlT0IZE9rfnNb7X6EoKHi2yCHAhm/Z1zV9FY9nrhLTmuXQAcLF
         vPuObMF9idJwAoAQxHHKhNG7DdpX7JUKLeGrFYT8j6rSXrvyOBTNyloaRcOIeS7zMDwE
         n8/4ROMSw2yHvNjI7FG+l18sXQ1fi+oEQ7+LGbUlx+Sg60VnFDqxA97B4jUxaXRdQzus
         gHRw1qZtkkn7TIoMdMPqP4sK2craIb9bdUHPF8GE4Y5NM3iJIj4m5U2OXDBeR/PL+zdo
         dQXsbQNLv6alPp7PcNxV3ssLc6NSWKvIl9GunHrdIXu5yJ2r/ns0KF64sj2Zd5SpwaqC
         WmBg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=leEz1fiyyYNCvStCVFZ11qKUfHMh+AfUoU9zFTvCrqA=;
        b=D9wO/M4Xp89ForTvvoVPDDaW4H5WMNAkadoVYuKbg4hHW396GREH13d4Byr//uplOm
         WRrHsxuUAoDwhn8waGZDrjLjw27CKt0nw7yCuTzfZ3X7nG12bczhA37cpwEGa97g7LU6
         tgmLSVb1iz/6Du/ev1VMNE9nA/Q8MgiXK+pRo6xeP3lZ0f75wp0UtEVC9swBOt6CCshR
         CysRN0N85DNma/cSiQXt8nlJWMzzFxC/5PsJVrM2scfP+fNahW/QEjAfZVo/aB+WYHxh
         gH3FMjOp+3fWuuild4pI79MXY5ndiGHVDFFQIuSfMc4UtgG8waWXGNhwsLyJ/TjWYohP
         jWag==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b="oHgSA/KC";
       spf=pass (google.com: best guess record for domain of willy@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=willy@infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:e::133])
        by gmr-mx.google.com with ESMTPS id k11si1520926ybb.4.2020.06.16.14.15.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 16 Jun 2020 14:15:24 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of willy@infradead.org designates 2607:7c80:54:e::133 as permitted sender) client-ip=2607:7c80:54:e::133;
Received: from willy by bombadil.infradead.org with local (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jlIv1-00069R-Gz; Tue, 16 Jun 2020 21:14:55 +0000
Date: Tue, 16 Jun 2020 14:14:55 -0700
From: Matthew Wilcox <willy@infradead.org>
To: Joe Perches <joe@perches.com>
Cc: Waiman Long <longman@redhat.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	David Howells <dhowells@redhat.com>,
	Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>,
	James Morris <jmorris@namei.org>,
	"Serge E. Hallyn" <serge@hallyn.com>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	David Rientjes <rientjes@google.com>,
	Michal Hocko <mhocko@suse.com>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Dan Carpenter <dan.carpenter@oracle.com>,
	David Sterba <dsterba@suse.cz>,
	"Jason A . Donenfeld" <Jason@zx2c4.com>, linux-mm@kvack.org,
	keyrings@vger.kernel.org, linux-kernel@vger.kernel.org,
	linux-crypto@vger.kernel.org, linux-pm@vger.kernel.org,
	linux-stm32@st-md-mailman.stormreply.com,
	linux-amlogic@lists.infradead.org,
	linux-mediatek@lists.infradead.org, linuxppc-dev@lists.ozlabs.org,
	virtualization@lists.linux-foundation.org, netdev@vger.kernel.org,
	linux-ppp@vger.kernel.org, wireguard@lists.zx2c4.com,
	linux-wireless@vger.kernel.org, devel@driverdev.osuosl.org,
	linux-scsi@vger.kernel.org, target-devel@vger.kernel.org,
	linux-btrfs@vger.kernel.org, linux-cifs@vger.kernel.org,
	linux-fscrypt@vger.kernel.org, ecryptfs@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-bluetooth@vger.kernel.org,
	linux-wpan@vger.kernel.org, linux-sctp@vger.kernel.org,
	linux-nfs@vger.kernel.org, tipc-discussion@lists.sourceforge.net,
	linux-security-module@vger.kernel.org,
	linux-integrity@vger.kernel.org
Subject: Re: [PATCH v4 0/3] mm, treewide: Rename kzfree() to kfree_sensitive()
Message-ID: <20200616211455.GB8681@bombadil.infradead.org>
References: <20200616015718.7812-1-longman@redhat.com>
 <fe3b9a437be4aeab3bac68f04193cb6daaa5bee4.camel@perches.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <fe3b9a437be4aeab3bac68f04193cb6daaa5bee4.camel@perches.com>
X-Original-Sender: willy@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20170209 header.b="oHgSA/KC";
       spf=pass (google.com: best guess record for domain of
 willy@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=willy@infradead.org
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

On Tue, Jun 16, 2020 at 11:53:50AM -0700, Joe Perches wrote:
> To this larger audience and last week without reply:
> https://lore.kernel.org/lkml/573b3fbd5927c643920e1364230c296b23e7584d.camel@perches.com/
> 
> Are there _any_ fastpath uses of kfree or vfree?

I worked on adding a 'free' a couple of years ago.  That was capable
of freeing percpu, vmalloc, kmalloc and alloc_pages memory.  I ran into
trouble when I tried to free kmem_cache_alloc memory -- it works for slab
and slub, but not slob (because slob needs the size from the kmem_cache).

My motivation for this was to change kfree_rcu() to just free_rcu().

> To eliminate these mispairings at a runtime cost of four
> comparisons, should the kfree/vfree/kvfree/kfree_const
> functions be consolidated into a single kfree?

I would say to leave kfree() alone and just introduce free() as a new
default.  There's some weird places in the kernel that have a 'free'
symbol of their own, but those should be renamed anyway.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200616211455.GB8681%40bombadil.infradead.org.
