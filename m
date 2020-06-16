Return-Path: <kasan-dev+bncBC4LN7MPQ4HRBRGTUH3QKGQEUUH4J5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id E46A41FA8E7
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Jun 2020 08:42:12 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id y23sf5945998lfy.0
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Jun 2020 23:42:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592289732; cv=pass;
        d=google.com; s=arc-20160816;
        b=lonAEpHZa/DZnMa54844oKfVctbEwb/5b1sREFP3KcOj+V+CktKCVfjtcZBkdPS1+S
         ILTmCTiTlFddn3BResd299dB5vyaruKROpAJW0Wh/Hg8jARGQq6tCKfFjELZi4Qlruem
         trilS0bI7agr1HtzJ+EBFfl8OtkFbp3O+wtx4D8ZpU4pMFkHp8K/9ig+SPH/eFaK+O9C
         zhLqk3mnuDrT+uYaK4eT1SPazTB/WTp+rObLyerfraBLZIw9t3yRbij6yBBOho5E9A0j
         /ZtbLBIWUxi5GC74HQjESsqM5J2u7j21fVg68j/Xn+cwvsCukFJicymEMdXJjs3t/+5T
         OAuA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=mtwSF8jtPb24v7MKLWRPztSQbuwK8xXp1EXJTcr7YbE=;
        b=ZJvGkPRVwOXx9P/UZEZywfpuzbQltmyyCfdtrW6/DHfhWAVOqjxS3TnVFJkvSh5CLl
         kz5zdnvl6pOmSCVgT1N4TuUYZ5JoptK5wUGeDNuVLx/E4nCe3jOwGhOFsBjmAgQaPtLg
         kB340sBkiXSPczIhxEIWqNwPgEqCeyA08bEm6d3CXJIFmJO7gExhBXhzHWckLeJG9xK/
         nNMi5kHjUtt2LW/iB6hCzr86KpGE+c3yqoXN1y2R9QwVpUygH7TG1+EGVEAyIqZG5xXX
         XnU8idQtS3l8DBDe9JIaw//SIZTW3aRVfdkCFSZMiW9aYDPWYq9wy4oAVD9c1PHxguXt
         wGeQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mstsxfx@gmail.com designates 209.85.218.65 as permitted sender) smtp.mailfrom=mstsxfx@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=mtwSF8jtPb24v7MKLWRPztSQbuwK8xXp1EXJTcr7YbE=;
        b=CVCHHizGjK9jZ1+bd/rEyfRrBWgbBPOEGkRaHrhGrmn7Cbo4ViqedzNx194aLXfkAK
         cCn3aLq7Y51hlx2t5qJFiTQ2Q95oj8A9hpOHlhviSiT5ToHSj4k81hnvW84GDMV5LUkL
         zLWwkXWJAXjsIUgOg/y2agbd4W8SVg+AP8Iezm+d66oeq1CjCwJqzCsWlWT4541PxGAf
         zaf4Qxs64iXAmPrTq1aLLI9MrNsjWBFXNwnz9GmB7g4pR0kmIjcVXxF2KPKLX6WAYXSS
         TXnzA4CdSCB0SiipJPSGUg7KAGT/06SNziSWj0LrjZHO954S3+C9+vj3ew3FStlyE/E2
         P0AQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=mtwSF8jtPb24v7MKLWRPztSQbuwK8xXp1EXJTcr7YbE=;
        b=pFuDeXr6lkEjco/PYUkqnmt8DPaMyLAUQJT9e8VeNvYV8WxG9XdY+8vacxSCwK6liT
         XO9LanepFPj5Z2hz43cBYB/uovf8kyXm/0hJrQ7oVDljW6yOuW/KOSR6W1zG3PO1tPlO
         FEU7d5KQ0fae544lvlFKSBPV5r1DY6WF9c+WMq1Ta7mQJANpFaqISCCMElql0uziahnd
         VI8Dmoth1rG7zJ+027TXUtVR48lhzsa5nmvH5hkhNQzjLcE+iRgez2vIdtZDRl2fJVmS
         KdaUIxCGgR9rvzeaDxk1d9Cy94WGAXeAB7U8XzNOqNri2ofleT+Zdpz4ofTg/1xfXWnq
         hbHw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530ghApDjH79dTo7ro1mXF+Ec2zRAOOG3zNE+TGd/xOBUORzOA3J
	ePjxR7TMvF1Urep0Wixlj9I=
X-Google-Smtp-Source: ABdhPJyQHNKSpi43WOATgNguhHKQQdnLDnbNbQFk3r8aQaX0P5qklgVxKuU5VSx2X9UsR+4+EEJGqQ==
X-Received: by 2002:a2e:8002:: with SMTP id j2mr665081ljg.158.1592289732397;
        Mon, 15 Jun 2020 23:42:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:3a02:: with SMTP id h2ls3112557lja.6.gmail; Mon, 15 Jun
 2020 23:42:11 -0700 (PDT)
X-Received: by 2002:a2e:8953:: with SMTP id b19mr694666ljk.187.1592289731721;
        Mon, 15 Jun 2020 23:42:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592289731; cv=none;
        d=google.com; s=arc-20160816;
        b=yaMah8VDq7p4XdKzoLfpQo+4xS6xf3yc36CJPkCLfvB0Lmzmx4Fhb+nH3y/ztZsdlC
         NHE4PudJqYfDyht91maz1ToIBdGiFC/bKKwzTYOt064XAOAk60Va+gvwvSCzOJlhsGaz
         k1aEUZWXlwnDYVWRjPoH1WrdbqOyUXGHmlgR5DcboXdeDNvzoIZ3fWgeY08zo2kP2rKG
         CrfkNyYPXQ7umoyL3plwr848lrCmOwMnFltXnxZnGaI3EAiSvNd8bTOAv3OLaqdW0vnc
         mGKeTA346x2eg6zZUumoMBq6w4LDCOzRFaNHvA9g6eT7I2kqpoNNsWCj4MUM7A7xWzAQ
         zc3Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=8yT+7Ta/B3BUGUR35Fz/0p22bghMwTUAxgTnwepounI=;
        b=sQzEsHesYcY/fjIRT5/C3Umvj98OTPh2dzI0Sutsy3nwshH5pjcF1jAHYmYRNVcMkA
         vJLRj3DrwrSu0zYOswwOnrnTyTKA2lzJypdzGhoTUejft0zEhjbCCQ9jlA3Ru8e+JzHk
         YL06m64EvQ2srvuoTXoOQV2beqEPYyk0oUfSIvCtY1qQFXLZucZSAFHajiNhsNcFYBAy
         j6frVbOhaUHxFeNq/fVfNuLnAgEOWDIDHTHa0kZMJWvvlkwtvYXe4SAtlynjX3vqMQjc
         MEnFmYt8kMm2uMQ2Q1Iy8xeXJ/MqfVndG8BzPXAdKLHeFWHfUUkb5ybAyrVLiPdlWCzb
         Tjxw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mstsxfx@gmail.com designates 209.85.218.65 as permitted sender) smtp.mailfrom=mstsxfx@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail-ej1-f65.google.com (mail-ej1-f65.google.com. [209.85.218.65])
        by gmr-mx.google.com with ESMTPS id a15si256094lfb.3.2020.06.15.23.42.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 15 Jun 2020 23:42:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of mstsxfx@gmail.com designates 209.85.218.65 as permitted sender) client-ip=209.85.218.65;
Received: by mail-ej1-f65.google.com with SMTP id w16so19715274ejj.5
        for <kasan-dev@googlegroups.com>; Mon, 15 Jun 2020 23:42:11 -0700 (PDT)
X-Received: by 2002:a17:906:ce2f:: with SMTP id sd15mr1306745ejb.445.1592289731375;
        Mon, 15 Jun 2020 23:42:11 -0700 (PDT)
Received: from localhost (ip-37-188-174-201.eurotel.cz. [37.188.174.201])
        by smtp.gmail.com with ESMTPSA id j10sm9734428edf.97.2020.06.15.23.42.09
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 15 Jun 2020 23:42:10 -0700 (PDT)
Date: Tue, 16 Jun 2020 08:42:08 +0200
From: Michal Hocko <mhocko@kernel.org>
To: Waiman Long <longman@redhat.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	David Howells <dhowells@redhat.com>,
	Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>,
	James Morris <jmorris@namei.org>,
	"Serge E. Hallyn" <serge@hallyn.com>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	Joe Perches <joe@perches.com>, Matthew Wilcox <willy@infradead.org>,
	David Rientjes <rientjes@google.com>,
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
	linux-integrity@vger.kernel.org, stable@vger.kernel.org
Subject: Re: [PATCH v4 1/3] mm/slab: Use memzero_explicit() in kzfree()
Message-ID: <20200616064208.GA9499@dhcp22.suse.cz>
References: <20200616015718.7812-1-longman@redhat.com>
 <20200616015718.7812-2-longman@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200616015718.7812-2-longman@redhat.com>
X-Original-Sender: mhocko@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mstsxfx@gmail.com designates 209.85.218.65 as
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

On Mon 15-06-20 21:57:16, Waiman Long wrote:
> The kzfree() function is normally used to clear some sensitive
> information, like encryption keys, in the buffer before freeing it back
> to the pool. Memset() is currently used for the buffer clearing. However,
> it is entirely possible that the compiler may choose to optimize away the
> memory clearing especially if LTO is being used. To make sure that this
> optimization will not happen, memzero_explicit(), which is introduced
> in v3.18, is now used in kzfree() to do the clearing.
> 
> Fixes: 3ef0e5ba4673 ("slab: introduce kzfree()")
> Cc: stable@vger.kernel.org
> Signed-off-by: Waiman Long <longman@redhat.com>

Acked-by: Michal Hocko <mhocko@suse.com>

Although I am not really sure this is a stable material. Is there any
known instance where the memset was optimized out from kzfree?

> ---
>  mm/slab_common.c | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
> 
> diff --git a/mm/slab_common.c b/mm/slab_common.c
> index 9e72ba224175..37d48a56431d 100644
> --- a/mm/slab_common.c
> +++ b/mm/slab_common.c
> @@ -1726,7 +1726,7 @@ void kzfree(const void *p)
>  	if (unlikely(ZERO_OR_NULL_PTR(mem)))
>  		return;
>  	ks = ksize(mem);
> -	memset(mem, 0, ks);
> +	memzero_explicit(mem, ks);
>  	kfree(mem);
>  }
>  EXPORT_SYMBOL(kzfree);
> -- 
> 2.18.1
> 

-- 
Michal Hocko
SUSE Labs

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200616064208.GA9499%40dhcp22.suse.cz.
