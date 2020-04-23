Return-Path: <kasan-dev+bncBDUNBGN3R4KRBW7BQT2QKGQEHWJ24YQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 626021B548F
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Apr 2020 08:08:28 +0200 (CEST)
Received: by mail-wr1-x437.google.com with SMTP id e5sf2307624wrs.23
        for <lists+kasan-dev@lfdr.de>; Wed, 22 Apr 2020 23:08:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1587622108; cv=pass;
        d=google.com; s=arc-20160816;
        b=P2fOE3g1rNL27hZdva2XwEjU4IxE/yLg9zCW0mbjOoPFuh46borZPg8S0+wm8PZVju
         gtDq0pxpv+t48Y7PBCnAdASGlUngP34K8HO9i+7FsFxa9IkdfeX5T7tqSrhpjuq5xPu3
         FkqNyuhiICWG0XOb/4uJV8gxUeVK/PYqs6y7vY2Zo5M99D+4vUMg9NX6ZcdgVxJO1Jtx
         5Cldw9kMqODTXg5m2pv2WqvyCGdqN88EizjgaQnqpfiDP7esIqHAIecmdg0p0B8vgoy1
         VqdwKgbrndEQ0lwLLFLDcQDIELfHinVUPxSBdTA5x3CrKV8slmiHnePNQrbWaJ+NRAqM
         PfJw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=o7GO+V3ZmxdIWZvWZ6GWAZUOtAV20J3l2gpUn51t0HY=;
        b=vEzv//kJDCs84XmLOa29BxuSuOLiKItpOmYNkw/O6JxNIAYM2YR2LmKCe0lhHp3n7S
         4KZDi+S9TaVBIYnwSipqZzBgyqQfU8wRCgQAjTFR6p+eOJzCbxrtKRw95OsmPQzHQ8uW
         X09Kh3erQAlGW9oGIBHq1I+Qpc+7ANE8Ew7kbuGI+R2pdCs9X4dcIEGcCsswsTkR1zgZ
         88Xc/Skeu/G7QoCL9Du7EJu4/votgBnFrLaZ7Br7gGhq3U5YKcAPt3PoqMEr027bSRf7
         GAqGIDA7FbK8t0VM3Hhwwktm19MzbvPSDQP1xa5Uzk7bMgjfzUnqvRIIgSjVDo9oUhOu
         McOQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of hch@lst.de designates 213.95.11.211 as permitted sender) smtp.mailfrom=hch@lst.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=o7GO+V3ZmxdIWZvWZ6GWAZUOtAV20J3l2gpUn51t0HY=;
        b=GwfrK69RAVtE+CiY06xJLffKQVrb0rUV0/JXswe4MDBRjoPCd10CH9disJfVOsr8BA
         KCk7JXlINpSIn1aGNQNlmetkdVEMrqh9LxpauY94ERu6CVN8eS/EpM5ChgNkz0w92Ejx
         5qSPh+HfgYJSIh5G+o+frmpBaKGDn1uUYQUI2wfnzQlsRaXhX4lRRvKi79CGYtZrjqyV
         sZGE2xw8IwtE7TYQuMwZSnsJvRu1UVQmnysP2CRrc9+O6AVZs3t6Vvqu6lY0DVLA0IyL
         AWWXoOYqbSxEhaiojXCOaMiOuaeyN9gZrkTvpNRUcnjz0noj9n+1T9MCg5khtDcDFrvN
         ukDQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=o7GO+V3ZmxdIWZvWZ6GWAZUOtAV20J3l2gpUn51t0HY=;
        b=uNLv2IKAQjgtRFEhOp/VTQI2UT/Jy+hM9SXRYfkdQy0CFS+2nXFg5UjBidLfnO/rl/
         j7kPfpuwYe7mBZkQQWP85ckr1++HQ6xkIiND8ZxyLcJYJntJ7ENCq5W4rF/6AJdzTiAo
         GqXeXhN5U5Aji66PRncL0BOhEGXnEdiSxk2DxAnvj2YUyPilJ2m5G7ty3chUyOPR1p4B
         Kow/XHJzYdC6N/VHK4ufEbQ0dBpE1rC/Hj6APQNloTDnZwwY3/EhwDK9puEXco5IyCSj
         d5eNQcd8Qioj7DE0hVVOY6AH6OOKjnVtJk2qjC5aHXk9AKTg9biUkMg7Xlh/BbVSYVTD
         btjw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0Pub2lJvSZ4gWmcnXgWX2vs56DkZq4GQnr/OU9P2l0BsFihQ9ZgCV
	0q+14ULzUAHQgOxEOoGC1zc=
X-Google-Smtp-Source: APiQypJyS8C/H8tPq3BaPACAQSljr2zH16kkl1U0Sd6T1QQxvzJgc9eHnj+wozYC1pIX2P3HeWLmgg==
X-Received: by 2002:a5d:5652:: with SMTP id j18mr3163059wrw.40.1587622108102;
        Wed, 22 Apr 2020 23:08:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:7d12:: with SMTP id y18ls2702852wmc.2.gmail; Wed, 22 Apr
 2020 23:08:27 -0700 (PDT)
X-Received: by 2002:a1c:c2d6:: with SMTP id s205mr2355046wmf.90.1587622107427;
        Wed, 22 Apr 2020 23:08:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1587622107; cv=none;
        d=google.com; s=arc-20160816;
        b=qIF9b8tmVlNiKKf7zG6ZnNDAcJ5Yq0MYBabdTo8TrPPrAqRLW1JcKCbiRWMTHkYggY
         wp+STi2sOFqvWrA++yi9Qzj0z+D3Z8/KoB1RQCT60xcyMsPyGqmoFNIQJKuLkzJlvpkJ
         FSvDIwizbf7VPj+HwCq29l+Tdy2r0QtPuzUrv88ehB6LJUMMdlb7YMbw/kH5kqNao+ts
         1/+4zFrkjm8X8GD5zSlLSS4XTmHlfEcvaNlrBLqNkTgvZrA5OBUSAbWzAvBgzwQ9Tndd
         q/2zqsAoSvdP9iX39tSo/70yihc+I9C82qIamk9GiWUm107luog9Uy7exucfxs1UpZhl
         JN1Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=n946m32U5RX4ynSjxAACPq7OuvJtrbnDvIT/eyg+sag=;
        b=AwDrQSz0eL4qxeJmCh+ZkT879TNTYUJ59aIyOwAtwIjm2RbVIdgZwc9KrDk4Iqc0lE
         PXMOVM0AxsMynrvlNSbEQzfA3AVB9pHYCkfsTXW0e7ycIsqSnh1oXB2iaxoG6/SD3/u8
         OkkBVYPjuXsDtvVQmSHt4Ndd/k4nZXwNR/n33jwS1n1slBxIptI5DfXKX+KKyFiSt7f1
         1A6uYC7tReeWCFb4I22/ASniSdQaChcNGMaCWubIgx/YUP8LFPgnk/SF4A5zxX3lvOC6
         TnrixFHJbCr7Raa7bIktDXXa6mgjkm6zNOFrvUFLZgLMUY6DRG9Mwhf4ExmahxVr7ioX
         raDA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of hch@lst.de designates 213.95.11.211 as permitted sender) smtp.mailfrom=hch@lst.de
Received: from verein.lst.de (verein.lst.de. [213.95.11.211])
        by gmr-mx.google.com with ESMTPS id y1si79353wrh.1.2020.04.22.23.08.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 22 Apr 2020 23:08:27 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of hch@lst.de designates 213.95.11.211 as permitted sender) client-ip=213.95.11.211;
Received: by verein.lst.de (Postfix, from userid 2407)
	id BF29E227A81; Thu, 23 Apr 2020 08:08:25 +0200 (CEST)
Date: Thu, 23 Apr 2020 08:08:25 +0200
From: Christoph Hellwig <hch@lst.de>
To: Borislav Petkov <bp@alien8.de>
Cc: Qian Cai <cai@lca.pw>, Christoph Hellwig <hch@lst.de>,
	"Peter Zijlstra (Intel)" <peterz@infradead.org>,
	x86 <x86@kernel.org>, LKML <linux-kernel@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: AMD boot woe due to "x86/mm: Cleanup pgprot_4k_2_large() and
 pgprot_large_2_4k()"
Message-ID: <20200423060825.GA9824@lst.de>
References: <20200422214751.GJ26846@zn.tnic> <462564C5-1F0F-4635-AAB8-7629A6379425@lca.pw> <20200422220512.GK26846@zn.tnic>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200422220512.GK26846@zn.tnic>
User-Agent: Mutt/1.5.17 (2007-11-01)
X-Original-Sender: hch@lst.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: best guess record for domain of hch@lst.de designates
 213.95.11.211 as permitted sender) smtp.mailfrom=hch@lst.de
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

On Thu, Apr 23, 2020 at 12:05:12AM +0200, Borislav Petkov wrote:
> On Wed, Apr 22, 2020 at 05:57:09PM -0400, Qian Cai wrote:
> > I thought Christ is going to send some minor updates anyway, so it may
> > be better for him to include this one together? Otherwise, I am fine to
> > send this one standalone.
> 
> You mean Christoph.
> 
> Ok, I'll let you guys hash it out.

I can send one, but given that Qian found it and fixed it I'd have
to attribute it to him anyway :)

This assumes you don't want a complete resend of the series, of course.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200423060825.GA9824%40lst.de.
