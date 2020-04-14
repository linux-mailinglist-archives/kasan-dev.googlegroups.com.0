Return-Path: <kasan-dev+bncBCXLBLOA7IGBBYVG2X2AKGQEBUIJRFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id E96341A734F
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Apr 2020 08:08:34 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id h22sf2254808wml.1
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Apr 2020 23:08:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1586844514; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ia45q8bPKzN5n3aIE0ITkqcghFatFGuB17mg/p5+LmZgjXR91ARjW2dIRMu1PDKyF3
         PSjNV5jv1oVXVkRGivG0l5cjZ7zJqKxo4vs3AOf+RS/DTlKT0SHJFdDET6RDQKz6uxA9
         H1vv2cYT0q8kF0XTgEFPv6W8hz1CBsx2dXy/kxzVGwh4llGCHuuluYO4dhYy38SBF3Um
         WcSIWF2A077UOJ9DmSIKQYTmLQ/UP1JwOfSM3D/hCmY5csbrxnTu/lAOgYXRGEF6nrzK
         4uKjUF2OAtnHaUbWP6UFybXly60ACJBHN5go5MDu7LuMM0bHT8h6FxxgDJzaukiaFXz3
         fOwQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=szxnmX6Wc1REO5wgQUEq9rJH73xM1lXpnGDgw//K6FQ=;
        b=LJQRk+9MSavQfdxa8LYTYPZM0YIgZFZXtwAn1EMhcy8HfwHD12LCufpZAIWcT8ReMZ
         c+z2doIJaBM2kSWgqUnGjVpbTqWMfuklNHEn/cQv6/Jfkq3FDNXDSTw3ckyTcqhEIy51
         nf8Gegp1Vw2AvEM+1wcvpD6Zt2M/rYUtYjtAITzbG1smXLa1oWGzCYK4Hlm8v4XIRJQ9
         oIs/UOJ3q9+sNVAvMbjBkdbHaWMTqaOZfMDtEF2APOzmrxG3S9INImNdFrWs4EsWtMdl
         Ls2IvYmT9jBz7KNZ4g4G41h5wdypgxri/Ecq7O2VDR7fSmhn8BzrxWzLwfzDdrYGd20D
         G1Gg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@c-s.fr header.s=mail header.b=swLCNyX7;
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=szxnmX6Wc1REO5wgQUEq9rJH73xM1lXpnGDgw//K6FQ=;
        b=f7ZT1cjvAXxGwJ07JlQDHXXv/3ZofjMZku3sehTE/DJMdQaV65idKIUuPWYK3vTBzP
         GH390QuiAbhlb+ETmzQRBy2lRbzkEgA05jQukKphyNJO2d/lGX4KJapZasnpQ961kr7X
         ZjsiW2TIsxwzaNYLKL0fD1NR+z1I6tl7l7Ce3dVExbOyxsaXNUL5WbBFnY/5swAFL+2F
         bE7/JdJ7/Znjw36GU7Le+jygQfEeUxTkfefgMno2llEXbss9/aKXClHj1XkAQF3te2SQ
         bmOcuFDr9yaxEajB9jlhmoWwkoTpwxN2luGl9lH/WW6HC2P1PZyw889DNn+8v+7Rb6BS
         OQlA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=szxnmX6Wc1REO5wgQUEq9rJH73xM1lXpnGDgw//K6FQ=;
        b=JwuZn2oRen9Emmd4mtfH6G2YvNHnEj7/17ZxSY4+dZXHDRSiOFbi3f4U/3JpYZM3Hq
         IEJkDqcnavi8bbJtHnq5oYP2qnluTOMtKq6NMcY5Tp2CA8JBczGFiRhUy7IRFWIAMbi4
         LTHlbJUSndtYYTWcz2mDWM39TKwuZ+1WGT36cIGxyEINpnj74kPXETU9szQAzaobps4Q
         8Q3DVVMcY5fHWjXtA8kL83kEjNNZorkIMm2+H+y8sSVHlbamwO/h8mNPY5hDeivk563h
         kGsruCOBj4R3ijEShwxmfCN7e4cYg7iMSNHVebv6sGu6SwRZKCJEVY9OAxPnLAuVNAiy
         8EkQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuaLkEXwAD0QGSNdfObuKspXu65sTQGf8iyGgps9fqr+ojQj5b3g
	YbkdMdf2DE28S3Tdau/s7bU=
X-Google-Smtp-Source: APiQypIPsCC3rsKdwhciogx2hBjpEoue3vlS2ZiAV6AYnJX+zuZSrx9+xcrWBeAvtgO5bSDXqsU6sg==
X-Received: by 2002:adf:df8e:: with SMTP id z14mr23217443wrl.296.1586844514625;
        Mon, 13 Apr 2020 23:08:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:5644:: with SMTP id k65ls2581081wmb.1.gmail; Mon, 13 Apr
 2020 23:08:34 -0700 (PDT)
X-Received: by 2002:a1c:e203:: with SMTP id z3mr22715361wmg.71.1586844514099;
        Mon, 13 Apr 2020 23:08:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1586844514; cv=none;
        d=google.com; s=arc-20160816;
        b=kA14imDo5JlNFu/o1jTdDFIEazINfbKA8wxxGcGqwZjV+c/4KW0SxZN6KCams2ZCpo
         UZnmGmb7lW+ABJgTtLZMqC+tED4aa5rAhyNIPI2Al0JffnjWoZ9QTGyQbMkFocuE1x+g
         jkQRIS8HOhVUaJDAZIVx8PIqw9zvPJlcoAy8sJY9hkO8pa0zGbUc6kVfGWBncnwp8+PC
         WEfRSm9gjXcp4zV2Juo/alZePRZP5vRZQT9qyo1NxjlQdEwq4JwfSUNHH9Hw1MeCA2oM
         uh8XvS13buwywiNlH2clSPSuFO3O5YPaQhU5xvQS2i0xMnyR2o1wfmD0GhHpSjl3Bq7M
         SEBQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :dkim-signature;
        bh=AyML/oaUiIiNPJKHTIdsIrbz6fYQpNyy/73cMAJtVGI=;
        b=fqsEHyB7YYuBzhORuAM5WYWv+d9aXt242+ENXLkgpCASzXonE76N9xx3i3yXeFtIkR
         2eOkp4oIo1IG5iF4OfmrkXiwyT4XyXQxVxksXzZY9lPl3cj0DQbCAke2ae9H3zgNI+45
         XFA6adJRiSuOWO2Vl66x4aO27YFbMu8yrOBbgkBi2siH9DfKjVyYOe55c3gTYHrIFH9c
         a56EBE/W3d2OKaGBBqwvBf86zJ2rVFoSn+ISSyQ56k956VokZMXZ7VpgOeC04Wx80Qde
         y/1VsjD2qhDTAq0uTKuSC9Ze6e6drQaqrmiIzHgetTSV04X0HNtfyZk5/Z2l9wkOyjfU
         t0VA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@c-s.fr header.s=mail header.b=swLCNyX7;
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id u25si800226wmm.3.2020.04.13.23.08.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 13 Apr 2020 23:08:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub1-int [192.168.12.234])
	by localhost (Postfix) with ESMTP id 491Zmc64yLz9txkH;
	Tue, 14 Apr 2020 08:08:32 +0200 (CEST)
X-Virus-Scanned: Debian amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [192.168.12.234]) (amavisd-new, port 10024)
	with ESMTP id 4yni2YpdXT3P; Tue, 14 Apr 2020 08:08:32 +0200 (CEST)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 491Zmc4L0Rz9txkG;
	Tue, 14 Apr 2020 08:08:32 +0200 (CEST)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 5B4A48B77D;
	Tue, 14 Apr 2020 08:08:33 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id IsbJC8uJ2iOV; Tue, 14 Apr 2020 08:08:33 +0200 (CEST)
Received: from [192.168.4.90] (unknown [192.168.4.90])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 997728B752;
	Tue, 14 Apr 2020 08:08:30 +0200 (CEST)
Subject: Re: [PATCH v2 2/2] crypto: Remove unnecessary memzero_explicit()
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
 <20200413222846.24240-1-longman@redhat.com>
From: Christophe Leroy <christophe.leroy@c-s.fr>
Message-ID: <eca85e0b-0af3-c43a-31e4-bd5c3f519798@c-s.fr>
Date: Tue, 14 Apr 2020 08:08:22 +0200
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:68.0) Gecko/20100101
 Thunderbird/68.7.0
MIME-Version: 1.0
In-Reply-To: <20200413222846.24240-1-longman@redhat.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: fr
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: christophe.leroy@c-s.fr
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@c-s.fr header.s=mail header.b=swLCNyX7;       spf=pass (google.com:
 domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted
 sender) smtp.mailfrom=christophe.leroy@c-s.fr
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



Le 14/04/2020 =C3=A0 00:28, Waiman Long a =C3=A9crit=C2=A0:
> Since kfree_sensitive() will do an implicit memzero_explicit(), there
> is no need to call memzero_explicit() before it. Eliminate those
> memzero_explicit() and simplify the call sites. For better correctness,
> the setting of keylen is also moved down after the key pointer check.
>=20
> Signed-off-by: Waiman Long <longman@redhat.com>
> ---
>   .../allwinner/sun8i-ce/sun8i-ce-cipher.c      | 19 +++++-------------
>   .../allwinner/sun8i-ss/sun8i-ss-cipher.c      | 20 +++++--------------
>   drivers/crypto/amlogic/amlogic-gxl-cipher.c   | 12 +++--------
>   drivers/crypto/inside-secure/safexcel_hash.c  |  3 +--
>   4 files changed, 14 insertions(+), 40 deletions(-)
>=20
> diff --git a/drivers/crypto/allwinner/sun8i-ce/sun8i-ce-cipher.c b/driver=
s/crypto/allwinner/sun8i-ce/sun8i-ce-cipher.c
> index aa4e8fdc2b32..8358fac98719 100644
> --- a/drivers/crypto/allwinner/sun8i-ce/sun8i-ce-cipher.c
> +++ b/drivers/crypto/allwinner/sun8i-ce/sun8i-ce-cipher.c
> @@ -366,10 +366,7 @@ void sun8i_ce_cipher_exit(struct crypto_tfm *tfm)
>   {
>   	struct sun8i_cipher_tfm_ctx *op =3D crypto_tfm_ctx(tfm);
>  =20
> -	if (op->key) {
> -		memzero_explicit(op->key, op->keylen);
> -		kfree(op->key);
> -	}
> +	kfree_sensitive(op->key);
>   	crypto_free_sync_skcipher(op->fallback_tfm);
>   	pm_runtime_put_sync_suspend(op->ce->dev);
>   }
> @@ -391,14 +388,11 @@ int sun8i_ce_aes_setkey(struct crypto_skcipher *tfm=
, const u8 *key,
>   		dev_dbg(ce->dev, "ERROR: Invalid keylen %u\n", keylen);
>   		return -EINVAL;
>   	}
> -	if (op->key) {
> -		memzero_explicit(op->key, op->keylen);
> -		kfree(op->key);
> -	}
> -	op->keylen =3D keylen;
> +	kfree_sensitive(op->key);
>   	op->key =3D kmemdup(key, keylen, GFP_KERNEL | GFP_DMA);
>   	if (!op->key)
>   		return -ENOMEM;
> +	op->keylen =3D keylen;

Does it matter at all to ensure op->keylen is not set when of->key is=20
NULL ? I'm not sure.

But if it does, then op->keylen should be set to 0 when freeing op->key.

>  =20
>   	crypto_sync_skcipher_clear_flags(op->fallback_tfm, CRYPTO_TFM_REQ_MASK=
);
>   	crypto_sync_skcipher_set_flags(op->fallback_tfm, tfm->base.crt_flags &=
 CRYPTO_TFM_REQ_MASK);
> @@ -416,14 +410,11 @@ int sun8i_ce_des3_setkey(struct crypto_skcipher *tf=
m, const u8 *key,
>   	if (err)
>   		return err;
>  =20
> -	if (op->key) {
> -		memzero_explicit(op->key, op->keylen);
> -		kfree(op->key);
> -	}
> -	op->keylen =3D keylen;
> +	kfree_sensitive(op->key);
>   	op->key =3D kmemdup(key, keylen, GFP_KERNEL | GFP_DMA);
>   	if (!op->key)
>   		return -ENOMEM;
> +	op->keylen =3D keylen;

Same comment as above.

>  =20
>   	crypto_sync_skcipher_clear_flags(op->fallback_tfm, CRYPTO_TFM_REQ_MASK=
);
>   	crypto_sync_skcipher_set_flags(op->fallback_tfm, tfm->base.crt_flags &=
 CRYPTO_TFM_REQ_MASK);
> diff --git a/drivers/crypto/allwinner/sun8i-ss/sun8i-ss-cipher.c b/driver=
s/crypto/allwinner/sun8i-ss/sun8i-ss-cipher.c
> index 5246ef4f5430..0495fbc27fcc 100644
> --- a/drivers/crypto/allwinner/sun8i-ss/sun8i-ss-cipher.c
> +++ b/drivers/crypto/allwinner/sun8i-ss/sun8i-ss-cipher.c
> @@ -249,7 +249,6 @@ static int sun8i_ss_cipher(struct skcipher_request *a=
req)
>   			offset =3D areq->cryptlen - ivsize;
>   			if (rctx->op_dir & SS_DECRYPTION) {
>   				memcpy(areq->iv, backup_iv, ivsize);
> -				memzero_explicit(backup_iv, ivsize);
>   				kfree_sensitive(backup_iv);
>   			} else {
>   				scatterwalk_map_and_copy(areq->iv, areq->dst, offset,
> @@ -367,10 +366,7 @@ void sun8i_ss_cipher_exit(struct crypto_tfm *tfm)
>   {
>   	struct sun8i_cipher_tfm_ctx *op =3D crypto_tfm_ctx(tfm);
>  =20
> -	if (op->key) {
> -		memzero_explicit(op->key, op->keylen);
> -		kfree(op->key);
> -	}
> +	kfree_sensitive(op->key);
>   	crypto_free_sync_skcipher(op->fallback_tfm);
>   	pm_runtime_put_sync(op->ss->dev);
>   }
> @@ -392,14 +388,11 @@ int sun8i_ss_aes_setkey(struct crypto_skcipher *tfm=
, const u8 *key,
>   		dev_dbg(ss->dev, "ERROR: Invalid keylen %u\n", keylen);
>   		return -EINVAL;
>   	}
> -	if (op->key) {
> -		memzero_explicit(op->key, op->keylen);
> -		kfree(op->key);
> -	}
> -	op->keylen =3D keylen;
> +	kfree_sensitive(op->key);
>   	op->key =3D kmemdup(key, keylen, GFP_KERNEL | GFP_DMA);
>   	if (!op->key)
>   		return -ENOMEM;
> +	op->keylen =3D keylen;

Same comment as above.

>  =20
>   	crypto_sync_skcipher_clear_flags(op->fallback_tfm, CRYPTO_TFM_REQ_MASK=
);
>   	crypto_sync_skcipher_set_flags(op->fallback_tfm, tfm->base.crt_flags &=
 CRYPTO_TFM_REQ_MASK);
> @@ -418,14 +411,11 @@ int sun8i_ss_des3_setkey(struct crypto_skcipher *tf=
m, const u8 *key,
>   		return -EINVAL;
>   	}
>  =20
> -	if (op->key) {
> -		memzero_explicit(op->key, op->keylen);
> -		kfree(op->key);
> -	}
> -	op->keylen =3D keylen;
> +	kfree_sensitive(op->key);
>   	op->key =3D kmemdup(key, keylen, GFP_KERNEL | GFP_DMA);
>   	if (!op->key)
>   		return -ENOMEM;
> +	op->keylen =3D keylen;

Same comment as above.

>  =20
>   	crypto_sync_skcipher_clear_flags(op->fallback_tfm, CRYPTO_TFM_REQ_MASK=
);
>   	crypto_sync_skcipher_set_flags(op->fallback_tfm, tfm->base.crt_flags &=
 CRYPTO_TFM_REQ_MASK);
> diff --git a/drivers/crypto/amlogic/amlogic-gxl-cipher.c b/drivers/crypto=
/amlogic/amlogic-gxl-cipher.c
> index fd1269900d67..6aa9ce7bbbd4 100644
> --- a/drivers/crypto/amlogic/amlogic-gxl-cipher.c
> +++ b/drivers/crypto/amlogic/amlogic-gxl-cipher.c
> @@ -341,10 +341,7 @@ void meson_cipher_exit(struct crypto_tfm *tfm)
>   {
>   	struct meson_cipher_tfm_ctx *op =3D crypto_tfm_ctx(tfm);
>  =20
> -	if (op->key) {
> -		memzero_explicit(op->key, op->keylen);
> -		kfree(op->key);
> -	}
> +	kfree_sensitive(op->key);
>   	crypto_free_sync_skcipher(op->fallback_tfm);
>   }
>  =20
> @@ -368,14 +365,11 @@ int meson_aes_setkey(struct crypto_skcipher *tfm, c=
onst u8 *key,
>   		dev_dbg(mc->dev, "ERROR: Invalid keylen %u\n", keylen);
>   		return -EINVAL;
>   	}
> -	if (op->key) {
> -		memzero_explicit(op->key, op->keylen);
> -		kfree(op->key);
> -	}
> -	op->keylen =3D keylen;
> +	kfree_sensitive(op->key);
>   	op->key =3D kmemdup(key, keylen, GFP_KERNEL | GFP_DMA);
>   	if (!op->key)
>   		return -ENOMEM;
> +	op->keylen =3D keylen;

Same comment as above.

>  =20
>   	return crypto_sync_skcipher_setkey(op->fallback_tfm, key, keylen);
>   }
> diff --git a/drivers/crypto/inside-secure/safexcel_hash.c b/drivers/crypt=
o/inside-secure/safexcel_hash.c
> index 43962bc709c6..4a2d162914de 100644
> --- a/drivers/crypto/inside-secure/safexcel_hash.c
> +++ b/drivers/crypto/inside-secure/safexcel_hash.c
> @@ -1081,8 +1081,7 @@ static int safexcel_hmac_init_pad(struct ahash_requ=
est *areq,
>   		}
>  =20
>   		/* Avoid leaking */
> -		memzero_explicit(keydup, keylen);
> -		kfree(keydup);
> +		kfree_sensitive(keydup);
>  =20
>   		if (ret)
>   			return ret;
>=20


Christophe

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/eca85e0b-0af3-c43a-31e4-bd5c3f519798%40c-s.fr.
