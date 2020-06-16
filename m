Return-Path: <kasan-dev+bncBAABBX7ZUD3QKGQEV3UPH6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3a.google.com (mail-yb1-xb3a.google.com [IPv6:2607:f8b0:4864:20::b3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 49EED1FA6F6
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Jun 2020 05:30:40 +0200 (CEST)
Received: by mail-yb1-xb3a.google.com with SMTP id r17sf23281626ybj.22
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Jun 2020 20:30:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592278239; cv=pass;
        d=google.com; s=arc-20160816;
        b=JQDu0VIJQPCM22ZiwJ9WNU542+BccWh/3lQKYoqjt1O26RvaXT9+Q05ZsLjCH9f+jo
         BsSdZr8INUTA8ZvBDJ0dlT0uxS9AswrfmZnFYRXvTeaASEXEC9fzd+gKmMA4sgVI9tis
         EM4k6AtzAWpU8ML4dRk/GdI3Du309/e2iJKkkKcXrtI+vJrMTqPH9YbmZl23DmZOC0qw
         jD1xOp8E/zJHUzANfs7IFAiIKG8TqkeheiLTmFTRiJfSlirHAvd2v9O7t7DfTLMywqU5
         NiiBnypF5KiA442rehnfXt3GUkQcKHxOVuWAAGV0j3kxFqdrG4jnvu4/Z7KhUYR/elHs
         6Jug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=0wvj/WP6HQFZflhwDyj//8QUc+0+jtBkhRfMNKDKDHI=;
        b=bu0PwhiVVi5PZBr0G7beD67Pwowej/NfMoGsHhbbrfpyfxB1mO0aHz4Vd8ZcRVKeu2
         r4swVC6LdvCnoSDOX086L+/msmb3+8pwJejRvxczHf+XLUsqrHA6jUG8ISziAEh6eAvh
         Y1CC/KhrvibjP4f7n0GqnXE/WrDZo0ue/FcnnOyeoGDyC5NS/HxbioxHOTh9P2Wrrrcb
         z+EYhhB2uEo2OpXHt3YUF2pJ6enQftSy6Is4l2QrvVTkGXcgCQnCpATff0bwB9O96KYX
         I72iUFIW6K39oPz7X9EblDZQNAZGLQPmJEGso8M/hjnP57kBKQmpDPlklyy1dnN374cx
         4xRA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=CI14aWxQ;
       spf=pass (google.com: domain of ebiggers@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=ebiggers@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=0wvj/WP6HQFZflhwDyj//8QUc+0+jtBkhRfMNKDKDHI=;
        b=k2zqYsPQpNXv3ZwlBUMYz1+kzSd1ttlK9sV5iQsBNvGr6GWL0gA73WN3FixKf78aMJ
         TtqQINo+7uUdWlmYdpZ90XNL5fYTlOgeo+Nczq6zhBCUrFpFyFP0Ih4AdX8R4JUEFJB3
         sX5T4gyLfG6bNa+aha50ET4u1HR8J6QD5GY8kY2pYebb5mloK7TFksOVUu55PhPcIkyP
         nnzCo9EZmdfNxhpbIJEy8iihqLm0WBUgQNcMTLtWI0ykN9+CztmKKF810380WCwXPNFf
         1ahu642ZLwNuMCJ05XRMu+fVBjDCEM5gwaTkCqpx5ahJVhCESz8XrlBc/vGfP/DOAkCA
         d9XA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=0wvj/WP6HQFZflhwDyj//8QUc+0+jtBkhRfMNKDKDHI=;
        b=VRyXiqmkiQd6Dn2fZqlRnOwAKT9Yy13e3spOzZyDLe6/ETwcVHf3Jk+yvU/bCtUtsg
         Xh8oWaZBbau5QR2sBQSnWv49ELh6LwbC5fea2c/ozh+qhE7HRmODjr0cXiioh2e8Mpbg
         zp3GZXhpr41mDB2qpBGUoqNoJvHKM9GCJwF8gDTGFoNJaQ2AV7yCzvD2aJVDAUNJ6zKc
         eA1kJgCVunZWgjvnydABLpcTwvQ4QabP8PPE5VerLz2Qbkkq2ks43kjbX2q+t8Y1868l
         RPZohfXE4gly6RIibG6pusUVBRB6J7KwCMRBjbV3vOFyjE1xSD3d4Y3Zzi+Dw5jukvkB
         PQTg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533g5jPyBCcldxH2vYzkv26ZOhQUwU6g3heLyqHH+1Y9hA7RgIZp
	+ZUS9MtKpTls1WtDQY91X6c=
X-Google-Smtp-Source: ABdhPJxj5HPvuRmzcbuAPl8SB1t/cHjnArdqV6TIWFvaRxQoKZMJOp3EJ3/Vhmn2EHScaw+8JeT4wg==
X-Received: by 2002:a5b:282:: with SMTP id x2mr1048279ybl.304.1592278239138;
        Mon, 15 Jun 2020 20:30:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:ec5:: with SMTP id 188ls6810321ybo.11.gmail; Mon, 15 Jun
 2020 20:30:38 -0700 (PDT)
X-Received: by 2002:a25:ca45:: with SMTP id a66mr1139761ybg.164.1592278238859;
        Mon, 15 Jun 2020 20:30:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592278238; cv=none;
        d=google.com; s=arc-20160816;
        b=ReGWXLWTGKnD8L3l2D8Z08bwke1MrYfPwmTXAqDdig1a3kqh1pAYNb0XW+IrrjYNXq
         Z0OpmXbp26Su00+FJbQKg7Iy5QtUOZNCAcEcEr2RQ2G+ZZ14WhMyEkHLiCLB+ttpb7lk
         JYT/FMFtmByWqgMfVl9AuMIWob68Ul1eOZAC/D1xFu2ry/Mq2xMolT3v0MCiLQK2Xhc2
         9CDt94s/4eFdaU4LVHR/qiRb0xLzJ2iDzVw97/4A6A/txb4mw9ALpmldaWIuFP+CMxfk
         MyQjPniAqcnZW/TMJX5gBhDBWNNOglW3yPGijKYyVSSg+o/uTeni/F2q8XwvTMyvRTd7
         s3vA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=ZZSXdQV3Yi4q5M7xgKJGjciG2Rg5QHTatGL0GaU/Jo0=;
        b=Yey9W3icnTRpQ6QcBV0E0Cig2sy0tf3fpPAn2Z4hJFwOLIyt+LjLo8KuEi+9S0Mxah
         wj0j/pf92Yl6MANZSeL/z21Ot05vtRb/A4Cke/mTSXqVsJuQOp731vFMiTQHe+nOsiED
         BDMUhJXOubhsTl8EAGsXysYioH6iszO8sDvu8kXinU4OeEyy+iYAx3ubXAzp92A2o1wN
         Bu4AjOAeOmceUBLeZaEoqGWN7PFWjhi+WsmNu+8ABwDv+bDqBfjpu9JKo7LRhxy7vDTb
         HQS9Zv7AqcktcEDjBDojE76tYcSnm39k2AwMWNwxt88E3oz17CL9PqFGxAhGrKRYkV9b
         DSRA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=CI14aWxQ;
       spf=pass (google.com: domain of ebiggers@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=ebiggers@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id n63si985272ybb.1.2020.06.15.20.30.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 15 Jun 2020 20:30:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of ebiggers@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from sol.localdomain (c-107-3-166-239.hsd1.ca.comcast.net [107.3.166.239])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 9B3B8206D7;
	Tue, 16 Jun 2020 03:30:36 +0000 (UTC)
Date: Mon, 15 Jun 2020 20:30:35 -0700
From: Eric Biggers <ebiggers@kernel.org>
To: Waiman Long <longman@redhat.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	David Howells <dhowells@redhat.com>,
	Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>,
	James Morris <jmorris@namei.org>,
	"Serge E. Hallyn" <serge@hallyn.com>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	Joe Perches <joe@perches.com>, Matthew Wilcox <willy@infradead.org>,
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
	linux-integrity@vger.kernel.org, stable@vger.kernel.org
Subject: Re: [PATCH v4 1/3] mm/slab: Use memzero_explicit() in kzfree()
Message-ID: <20200616033035.GB902@sol.localdomain>
References: <20200616015718.7812-1-longman@redhat.com>
 <20200616015718.7812-2-longman@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200616015718.7812-2-longman@redhat.com>
X-Original-Sender: ebiggers@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=CI14aWxQ;       spf=pass
 (google.com: domain of ebiggers@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=ebiggers@kernel.org;       dmarc=pass (p=NONE
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

On Mon, Jun 15, 2020 at 09:57:16PM -0400, Waiman Long wrote:
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

This is a good change, but the commit message isn't really accurate.  AFAIK, no
one has found any case where this memset() gets optimized out.  And even with
LTO, it would be virtually impossible due to all the synchronization and global
data structures that kfree() uses.  (Remember that this isn't the C standard
function "free()", so the compiler can't assign it any special meaning.)
Not to mention that LTO support isn't actually upstream yet.

I still agree with the change, but it might be helpful if the commit message
were honest that this is really a hardening measure and about properly conveying
the intent.  As-is this sounds like a critical fix, which might confuse people.

- Eric

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200616033035.GB902%40sol.localdomain.
