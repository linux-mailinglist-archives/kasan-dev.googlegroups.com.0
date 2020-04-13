Return-Path: <kasan-dev+bncBDY3NC743AGBBPFV2P2AKGQE4UDEQ7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 1850D1A6E5A
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Apr 2020 23:33:49 +0200 (CEST)
Received: by mail-qv1-xf3d.google.com with SMTP id dc4sf5902402qvb.2
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Apr 2020 14:33:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1586813628; cv=pass;
        d=google.com; s=arc-20160816;
        b=OrSoZVw5G8xArj9J3nlQda5tgqWY/PqS6+6G/pSHu65ExzNi0wTWqIjrS9AUgzaLak
         1zXNRajqeJdpWimLQmR9sOZuGa82EE791bEmOEOpsAo6PjfqPPWMFnSyZz0oACfu2oQX
         Qvuf6C6PSnj4b6zduUmulzzOJgsKnzaaC3qpgcXjByiUd4Fjge9BjIJGnEO5bJXp/184
         7uY8XG1PLZOS375zgLyqICtAqrGngLHyBCDZ2mDnaosPRaeVKMcR4eUCRONdAIb/APQT
         9nu8hyRl6p3GxmIG8dqEUM9hR3xYVvC6URbO6l8ZOqdc0Wix0CnvYt13ftecPXPiogJE
         7qhQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:sender
         :dkim-signature;
        bh=2QsLrmDjKHCnPXJ1p7+za/j0YBn5FVs7sAQUal83nF0=;
        b=RbZ2y0VCZ628XhRTk0kROrKMxMR1vOqKv/RED1ZWq1kakCfAG6tRp7yTZ1Vqx3EYNP
         xigYUjG1xZFRsea6apqL74NJgFqvMibnZWRITR03Tuq7clFr5H6ClRl9XvodVHf4dRhl
         e+mvnJh4nD5a/icNBF6leb7pjq5mp8/QBRiKmv+chi30LurzKlXMuhmBQxBujQE2BCg9
         Ua+1EjFp7cQX/qlEzy3JvNQTCrwxsu67Ng7pPBRwsXDbECSRrcj8DXaswh1oYYEc6997
         LLh4sp+JqSCdU2M/XrPTau8qRZtJUaVm9oWPM2AsAfYRKsg1qK6mdwwip+AZ+easZrL9
         ElUA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 216.40.44.238 is neither permitted nor denied by best guess record for domain of joe@perches.com) smtp.mailfrom=joe@perches.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=2QsLrmDjKHCnPXJ1p7+za/j0YBn5FVs7sAQUal83nF0=;
        b=CLxB2K6ccmMK1G5bA88KcHF8RZGGY49IYaNa7bHGn20CPc9IwN7tHCYGIEqagn9mjH
         J+BZOiUhKlG5O9T1h7iW/2Fo1S5e32q2jhOMoKIfg96RqV+HFzbPMu3v93SxMVtrNr3G
         0y5/G9WHbzTpNB9pCfbZq7rsQvZlTU4B9rdPzp42Nlunp35S8ecs6mMHxYTzAhYiFXUX
         Se45zS/4TVIiElJj5G8/03AdpvXj9e2dNbc3HS75MO9v7Rv/DdooTyXTzZ57AZNKNTEg
         SzceFSg1zk4GA/D9ReQQTtm9I8jZM/G1shMbfHjxPedDPguXgqS5eX6h+7hTIRsX8Hc9
         cliQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2QsLrmDjKHCnPXJ1p7+za/j0YBn5FVs7sAQUal83nF0=;
        b=JKjtNoI+MzJPDD/4NJvCLQZadSwMm+nNaap8ctgaJSnuDAX9qyBX0ibq9Q00EVMiV5
         MDGYkwSESjAvXnBCYWwS2Elyz9eF2jQk6Rn9IlODx6Rx5xwZq+KS6HGg4g68a/nfyCeD
         MCwPLxfFb4WtSa1ctRMa+WnCyZD1IHGPN8CAmQyh3lmAmbG679bnPoUlw/dZ/JNkO0v+
         3Z17pJwQkt9h+IcR9PaV6Ftu0afArY677iZ74+ViAoQ6BbO69HMSBhWj6J2BOEMCkFJG
         GYMF6Hp30VK54EmBU5eaTKtBegDluLig3iiYafT2jLVjLG2XWyX8aV54xpNpjrMTLVEU
         u42g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuY02aEi12OrawZ2JnKwqW1KROvSZiTizykSJmk0rICzTioSkRlK
	dSlZNWB8S8fmU71P+TSrd8I=
X-Google-Smtp-Source: APiQypJDIVjBkN/c/cH8vZgJmXFVGyU4XY8/YEL+TItjoQjK1NnmMjr4wdN0mr9UEcR71d67BWgOHw==
X-Received: by 2002:ac8:7288:: with SMTP id v8mr13101929qto.31.1586813628133;
        Mon, 13 Apr 2020 14:33:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:2208:: with SMTP id o8ls561208qto.10.gmail; Mon, 13 Apr
 2020 14:33:47 -0700 (PDT)
X-Received: by 2002:ac8:6ec8:: with SMTP id f8mr11791567qtv.330.1586813627763;
        Mon, 13 Apr 2020 14:33:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1586813627; cv=none;
        d=google.com; s=arc-20160816;
        b=B+IXwvbkTbdxuyMhf/5BUFR7K8imqec03+eSG/YukVcjRFplLZn3kMhAt6bJromkFA
         SPlteCp3UAPJ2fWNIJV8dps4TE3gDL4eZOddSXaAncqMaXm+TAaGIeHoESxoI403eLkX
         nok7AzHGoxoLi1BoLPPJlmdWty1zpBvqVEqpmJH2FxPo00SpzeYYcyEBqHT6NW16QSFW
         8a/nKt3ulpiycjqhJW88HoKLYdCTer4ZteN9AwvdS7wWn3HO56Cy3ZLC1vXzOrnGU0Mr
         ob8LwS933KxSOk8d1odxEGifEYMojztZc1uwbLMuVMsRY/uK+RJqbPbMYCxzsJqrGhn/
         nPhg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id;
        bh=zlWGbTOB9joXsAgxkgX2tpua1ctVBKP5fRVz0EJLD7E=;
        b=TfSCsSrACDxFIWSZfQvZANDeB5vt2etXUWmOoyVx16OKPKsWKuLUgJJ/rnTC8NNK5M
         JSWhATUcKys3fe3NTPUZWSdoRQTH9sVN2gq2LLiofG6hkTbzSX7UfvmXAHulAapQX+tl
         iJSLhph8gHPlCcAnwUV88j5ptOInnyHGQIvNSlXHKQf9rUpoLTsy6LTmyfPoTTk+CueZ
         HaWkEQHiVrV04MShbajhzcv3G2aD3r6vPHgw3Vmyr4aGU4ZrJrsLqUKba/sq48moUTeF
         7IG+Fi/FwJhjsjD4/qg3YgtzWReu9Frfp9d2I0x8b5WhiV/sPXG7sxmCccafQFBTGhIa
         u5MA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 216.40.44.238 is neither permitted nor denied by best guess record for domain of joe@perches.com) smtp.mailfrom=joe@perches.com
Received: from smtprelay.hostedemail.com (smtprelay0238.hostedemail.com. [216.40.44.238])
        by gmr-mx.google.com with ESMTPS id 198si458400qkh.7.2020.04.13.14.33.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 13 Apr 2020 14:33:47 -0700 (PDT)
Received-SPF: neutral (google.com: 216.40.44.238 is neither permitted nor denied by best guess record for domain of joe@perches.com) client-ip=216.40.44.238;
Received: from filter.hostedemail.com (clb03-v110.bra.tucows.net [216.40.38.60])
	by smtprelay06.hostedemail.com (Postfix) with ESMTP id D45AF18027F9D;
	Mon, 13 Apr 2020 21:33:46 +0000 (UTC)
X-Session-Marker: 6A6F6540706572636865732E636F6D
X-Spam-Summary: 2,0,0,,d41d8cd98f00b204,joe@perches.com,,RULES_HIT:41:355:379:599:966:988:989:1260:1277:1311:1313:1314:1345:1359:1437:1515:1516:1518:1534:1541:1593:1594:1711:1730:1747:1777:1792:2196:2199:2393:2559:2562:2693:2828:3138:3139:3140:3141:3142:3352:3622:3865:3866:3867:3868:3871:3872:4321:4385:5007:6119:6742:6743:7808:8660:10004:10400:10466:10848:11026:11232:11657:11658:11914:12043:12048:12296:12297:12438:12740:12760:12895:13069:13148:13230:13311:13357:13439:14659:14721:21080:21451:21627:21990:30054:30091,0,RBL:none,CacheIP:none,Bayesian:0.5,0.5,0.5,Netcheck:none,DomainCache:0,MSF:not bulk,SPF:,MSBL:0,DNSBL:none,Custom_rules:0:0:0,LFtime:2,LUA_SUMMARY:none
X-HE-Tag: badge84_5a5696689f027
X-Filterd-Recvd-Size: 3380
Received: from XPS-9350.home (unknown [47.151.136.130])
	(Authenticated sender: joe@perches.com)
	by omf07.hostedemail.com (Postfix) with ESMTPA;
	Mon, 13 Apr 2020 21:33:40 +0000 (UTC)
Message-ID: <efd6ceb1f182aa7364e9706422768a1c1335aee4.camel@perches.com>
Subject: Re: [PATCH 2/2] crypto: Remove unnecessary memzero_explicit()
From: Joe Perches <joe@perches.com>
To: Waiman Long <longman@redhat.com>, Andrew Morton
 <akpm@linux-foundation.org>,  David Howells <dhowells@redhat.com>, Jarkko
 Sakkinen <jarkko.sakkinen@linux.intel.com>, James Morris
 <jmorris@namei.org>, "Serge E. Hallyn" <serge@hallyn.com>, Linus Torvalds
 <torvalds@linux-foundation.org>, Matthew Wilcox <willy@infradead.org>,
 David Rientjes <rientjes@google.com>
Cc: linux-mm@kvack.org, keyrings@vger.kernel.org,
 linux-kernel@vger.kernel.org,  x86@kernel.org,
 linux-crypto@vger.kernel.org, linux-s390@vger.kernel.org, 
 linux-pm@vger.kernel.org, linux-stm32@st-md-mailman.stormreply.com, 
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
Date: Mon, 13 Apr 2020 14:31:32 -0700
In-Reply-To: <20200413211550.8307-3-longman@redhat.com>
References: <20200413211550.8307-1-longman@redhat.com>
	 <20200413211550.8307-3-longman@redhat.com>
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.34.1-2
MIME-Version: 1.0
X-Original-Sender: joe@perches.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 216.40.44.238 is neither permitted nor denied by best guess
 record for domain of joe@perches.com) smtp.mailfrom=joe@perches.com
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

On Mon, 2020-04-13 at 17:15 -0400, Waiman Long wrote:
> Since kfree_sensitive() will do an implicit memzero_explicit(), there
> is no need to call memzero_explicit() before it. Eliminate those
> memzero_explicit() and simplify the call sites.

2 bits of trivia:

> diff --git a/drivers/crypto/allwinner/sun8i-ce/sun8i-ce-cipher.c b/drivers/crypto/allwinner/sun8i-ce/sun8i-ce-cipher.c
[]
> @@ -391,10 +388,7 @@ int sun8i_ce_aes_setkey(struct crypto_skcipher *tfm, const u8 *key,
>  		dev_dbg(ce->dev, "ERROR: Invalid keylen %u\n", keylen);
>  		return -EINVAL;
>  	}
> -	if (op->key) {
> -		memzero_explicit(op->key, op->keylen);
> -		kfree(op->key);
> -	}
> +	kfree_sensitive(op->key);
>  	op->keylen = keylen;
>  	op->key = kmemdup(key, keylen, GFP_KERNEL | GFP_DMA);
>  	if (!op->key)

It might be a defect to set op->keylen before the kmemdup succeeds.

> @@ -416,10 +410,7 @@ int sun8i_ce_des3_setkey(struct crypto_skcipher *tfm, const u8 *key,
>  	if (err)
>  		return err;
>  
> -	if (op->key) {
> -		memzero_explicit(op->key, op->keylen);
> -		kfree(op->key);
> -	}
> +	free_sensitive(op->key, op->keylen);

Why not kfree_sensitive(op->key) ?


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/efd6ceb1f182aa7364e9706422768a1c1335aee4.camel%40perches.com.
