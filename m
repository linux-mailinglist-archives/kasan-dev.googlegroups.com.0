Return-Path: <kasan-dev+bncBC4LN7MPQ4HRBT4EU73QKGQEXYP7CUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 9E28C1FC6C9
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Jun 2020 09:12:15 +0200 (CEST)
Received: by mail-wr1-x43c.google.com with SMTP id l1sf587718wrc.8
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Jun 2020 00:12:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592377935; cv=pass;
        d=google.com; s=arc-20160816;
        b=o94v/VQevaXvixPcMUWtEciG03iN/aMIwH4W0E1hEevpw6wHGCrn+2qv30nEPEb3WQ
         yruccxKD6QAJ37EWM5GAltGYIfW9C46fTFrrwKw5Ydr9sA/JVIS4tndtz7xLYCANSThW
         0yCYlnkVSBz6oOAI6LvoD+rcOET834l4RwJIJeyqNyT4fYQXt5z1YFLjybDGj0HsiA7x
         H3a5IfdgqlPEQ1bd/e5pXCDTqvOKda392TYfM+eiQtmsbMLsbW2J4jIUCUtutZ2ez6Oi
         zos5rBHaQCql3HHdSyDtRgvV6oNDlnXof043Se/ILUmAV2zgJVNfjEUBDcnXSBsiEXXv
         Be3Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=/AohkLET54+m/zzy6Aq21Mbg1p569QRaieYHC6gt/lg=;
        b=IfEj0cN54nfWPQ1DCodyg7UUlDMCJZ3nOCxykvW9fpiNTmhBnt8CdM0SWJ1eXN9vSv
         3hizQADcvbeXJg0uGjoytLrt0UIJtnnlUyC4RUgFOhCMRhc8FAzxZmwnEqRapkq4MWbR
         3fPJGL+/N8awFtQ/hR736+QPJwfIu4EcuyLBxSh6miyOYZGkaI2W0Tgfy0OK58PHEtuU
         PSYlM31afVCbwJjawgMQ01evtEZpGNqucfocD6qTGb7QyyJ814ppNdPRvqVpwsxYJ5ON
         zi+hwDJXyqrNetGfH9geLz9VkpODsLpGDz13uE6psE45O0kaA2CsxunkuI8Xppq7+5S9
         jafA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mstsxfx@gmail.com designates 209.85.218.67 as permitted sender) smtp.mailfrom=mstsxfx@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=/AohkLET54+m/zzy6Aq21Mbg1p569QRaieYHC6gt/lg=;
        b=grXnEn6qmhkRPvcdMwyQltwfkvk6Muj5e5kHqQq47a5mROYTxMmDNY2AYf2GaSQmUL
         +Cxdkb/Yn+YH2P7EtPDJrRRDo2hreiaIW1/il0UlINHWMMsiTprLaY9JXf8+CGmiN8IB
         DPOqY76RqgH5WCNNL5cdM8R1jcdnx3vgXCTRljdQ7lM/3toj+7Uri7QCMnFTGpb4kCux
         5zrLwJS/Eyqd9RAXM+sVypp8JfLE1kpXgqgBMQlY1QOaya6WNGI0Sv55jd+8ByvuAvEe
         bI0rTTWv0lAZy6mbIWguwKpADdcIe0s2pMv5oV+er1soV8JZiNOmp3S+rlEKaHfg0qg9
         U0aw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=/AohkLET54+m/zzy6Aq21Mbg1p569QRaieYHC6gt/lg=;
        b=Q5SQEuQKPdIGo418Jq3Sf5CeAHC8NwaIxxX7B8Qbp/O5qXq+CT73qkXdthkH4VBLwr
         4Zaju15+fXe6io94kd1NJX23xvCXKlxMwlXoRfQSXniWQBFCrH0ia2kmgTmkjjXSAscC
         1yquEIXEOSBbdHtEjdKPbJfhq8Qp1x8KZmiVgwg9dLAv9A10pDij+bQqn6enYhFvhACz
         QJG9KQ2QPF8CBFSFpNqgsQXWe/c4AwtrxdWarNohHY6+9kiNHxYwOU1WLC2znDS5WgU/
         56O4R4ycjegygMmqDJyaL0lOcGKJVwSQYp9YZy1ZDv4h1iHSYV0cw7EpyCcNjYVC91O+
         cKKw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM53392EQK1Px2m/dlM9eIlg6RQhq4pPLa9KGXSdIrdYI41Gcaynmh
	PsKlj9Nu7DpGoNPNnQTllmQ=
X-Google-Smtp-Source: ABdhPJw/c2Nh5lvg/T0equOuz1UsEajy8Veh/gW9Ij/ztG+Px7Faidn7IPywWjUxq0WDsP9lGBwsdQ==
X-Received: by 2002:adf:ef47:: with SMTP id c7mr7398762wrp.57.1592377935391;
        Wed, 17 Jun 2020 00:12:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:1d84:: with SMTP id d126ls533358wmd.1.gmail; Wed, 17 Jun
 2020 00:12:14 -0700 (PDT)
X-Received: by 2002:a05:600c:2215:: with SMTP id z21mr7144423wml.48.1592377934737;
        Wed, 17 Jun 2020 00:12:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592377934; cv=none;
        d=google.com; s=arc-20160816;
        b=K3mvXKQn+Di+pqg9Z84FPNCkzEqKZfURg3/G0HUprxtGp2pXcktVwaT+vlAv6WDl0x
         IUeprJg2SL/uCo0Rl4IQrHqBG2YhKoB29Uflot2MpPiYO+qh7t3afWZHRcniRNBDsK2p
         Z2gblpOV7z+s8CbyKuXnGJArVSB1bQH731LwY/aVCoZp9ndmZuWiERC0twIPAOf1SYg3
         AT79I4gww/ogrLRrNPHYa5ZxXYoE+E5SrG9pds0b3eBGqazcD3VQl5aW8NmqYQ7TsqSl
         cDgKHqUPGQEqOUJwOdrybWTUaBa34aaGf2gD3r5Y4D3vOPElOGS5tFIGn8wIgJfZ2qve
         mKSg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=E5EcWVbc+7tsS+GAmjqiwsU8zuC9ZQ4KDsXaJSfWulo=;
        b=TtAfpi+ql1E6FbCIDI/JJXff6bK/9PmPTp+Hg/h8/jWc8aaNI/iOEvnaXGKsfmWehU
         Dv/ZpQ3DnRCPN6/AaQgE2OuDXICQol8BVub/yg2IWDytfVhUmhgd35/qy3NyIm2/Z7Jt
         2HtgtShr7PFNUeZoVWSZXv/gwNy4ZJ3lNjNaXNEguIlnVfvYdkreKwB0CXEhCFuSiXWU
         IXFd1GyVfYl70yXxc4fbiO47v24GJ+2Z1JzNQzrCr0vwnH930KMbKdbBAvwVP5kvdlRD
         PbR0HP+VY4S1qOxYwXFHrODVw4IvyN7as4E80jHNC16mBJq1jzD+foACYgI4wTEq8meG
         Dr5w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mstsxfx@gmail.com designates 209.85.218.67 as permitted sender) smtp.mailfrom=mstsxfx@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail-ej1-f67.google.com (mail-ej1-f67.google.com. [209.85.218.67])
        by gmr-mx.google.com with ESMTPS id f1si1095958wrp.4.2020.06.17.00.12.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 17 Jun 2020 00:12:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of mstsxfx@gmail.com designates 209.85.218.67 as permitted sender) client-ip=209.85.218.67;
Received: by mail-ej1-f67.google.com with SMTP id l12so1133580ejn.10
        for <kasan-dev@googlegroups.com>; Wed, 17 Jun 2020 00:12:14 -0700 (PDT)
X-Received: by 2002:a17:906:2581:: with SMTP id m1mr6681797ejb.89.1592377934427;
        Wed, 17 Jun 2020 00:12:14 -0700 (PDT)
Received: from localhost (ip-37-188-158-19.eurotel.cz. [37.188.158.19])
        by smtp.gmail.com with ESMTPSA id g22sm12516138ejo.1.2020.06.17.00.12.13
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 17 Jun 2020 00:12:13 -0700 (PDT)
Date: Wed, 17 Jun 2020 09:12:12 +0200
From: Michal Hocko <mhocko@kernel.org>
To: Matthew Wilcox <willy@infradead.org>
Cc: dsterba@suse.cz, Joe Perches <joe@perches.com>,
	Waiman Long <longman@redhat.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	David Howells <dhowells@redhat.com>,
	Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>,
	James Morris <jmorris@namei.org>,
	"Serge E. Hallyn" <serge@hallyn.com>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	David Rientjes <rientjes@google.com>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Dan Carpenter <dan.carpenter@oracle.com>,
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
Message-ID: <20200617071212.GJ9499@dhcp22.suse.cz>
References: <20200616015718.7812-1-longman@redhat.com>
 <fe3b9a437be4aeab3bac68f04193cb6daaa5bee4.camel@perches.com>
 <20200616230130.GJ27795@twin.jikos.cz>
 <20200617003711.GD8681@bombadil.infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200617003711.GD8681@bombadil.infradead.org>
X-Original-Sender: mhocko@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mstsxfx@gmail.com designates 209.85.218.67 as
 permitted sender) smtp.mailfrom=mstsxfx@gmail.com;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

On Tue 16-06-20 17:37:11, Matthew Wilcox wrote:
> On Wed, Jun 17, 2020 at 01:01:30AM +0200, David Sterba wrote:
> > On Tue, Jun 16, 2020 at 11:53:50AM -0700, Joe Perches wrote:
> > > On Mon, 2020-06-15 at 21:57 -0400, Waiman Long wrote:
> > > >  v4:
> > > >   - Break out the memzero_explicit() change as suggested by Dan Carpenter
> > > >     so that it can be backported to stable.
> > > >   - Drop the "crypto: Remove unnecessary memzero_explicit()" patch for
> > > >     now as there can be a bit more discussion on what is best. It will be
> > > >     introduced as a separate patch later on after this one is merged.
> > > 
> > > To this larger audience and last week without reply:
> > > https://lore.kernel.org/lkml/573b3fbd5927c643920e1364230c296b23e7584d.camel@perches.com/
> > > 
> > > Are there _any_ fastpath uses of kfree or vfree?
> > 
> > I'd consider kfree performance critical for cases where it is called
> > under locks. If possible the kfree is moved outside of the critical
> > section, but we have rbtrees or lists that get deleted under locks and
> > restructuring the code to do eg. splice and free it outside of the lock
> > is not always possible.
> 
> Not just performance critical, but correctness critical.  Since kvfree()
> may allocate from the vmalloc allocator, I really think that kvfree()
> should assert that it's !in_atomic().  Otherwise we can get into trouble
> if we end up calling vfree() and have to take the mutex.

FWIW __vfree already checks for atomic context and put the work into a
deferred context. So this should be safe. It should be used as a last
resort, though.

-- 
Michal Hocko
SUSE Labs

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200617071212.GJ9499%40dhcp22.suse.cz.
