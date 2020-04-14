Return-Path: <kasan-dev+bncBCPILY4NUAFBBIFC3D2AKGQE55HPXSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x237.google.com (mail-oi1-x237.google.com [IPv6:2607:f8b0:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 0F85F1A8AF7
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Apr 2020 21:38:10 +0200 (CEST)
Received: by mail-oi1-x237.google.com with SMTP id i126sf11247661oif.0
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Apr 2020 12:38:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1586893089; cv=pass;
        d=google.com; s=arc-20160816;
        b=Cf0wREog9Xl3ZU9GS+klquBPZlTNU47xRvhmepKIBEhz2dJFqbWHO0EF104oECidAz
         3VbFOV6jqA6lQMWi3lXM5UOG2IobywwEQdfTuubxzzhPaf3+Xp8iPE+19E2ymGDP84HM
         HfA+sI9Djl0UHYcZB8g5WBfNDLJAZxvRvTW4jliWFP4NoW5h8SFKgda/xwRqKFJGENlI
         t4lxR1wqAW1go7rc+AVlHqmI3xcExOvOzu8cL0PQ1xmPdoB6T5rp659XdcFV6aOFAFZB
         eWvKK/DNQHOiJ+dMlxzmIDi7WmIZTooJs7OL9GFDY09W9mUaRYt5WjkwFUkzOHyTp/gW
         1lTQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:organization:from:references:cc:to:subject:sender
         :dkim-signature;
        bh=hyyc93OTy8Ay21UspMH9sB8pJ5OV+HYDKxGGSqCBBD8=;
        b=OtmthOGpbddAZCAg8F/Vh4mNHST8c1Olh19EqlknXrR6DeEEEd5Mpha2gLbMwzzwxt
         Qnfj7fJTBI39XrEya1zRpLYr5ZXEaQGvRwzAQoPkIRBc5YTMm1Mpc0GuiGJa6eoqy/vG
         7f53pkBncFpg+t59K3RRuW2DRxsV0fndDOYzLEHNhykWfnWvn0VTtjd7qN2+1XPS3Xwf
         xl4EtEEEowOTV1B6XmqToSWergSr5FZ6DQwBE5Y4hOGohWp6RJuLeoQ3r/dCPAH3KMx2
         7yDLphKZGVUF6Jgp+WPQGKf4eQmzY+moh04ka/XSoWlfKjTVtJUH4B1EVroMEBgim8R/
         a1Kg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Y4Qcwph2;
       spf=pass (google.com: domain of longman@redhat.com designates 207.211.31.81 as permitted sender) smtp.mailfrom=longman@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:organization:message-id:date
         :user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=hyyc93OTy8Ay21UspMH9sB8pJ5OV+HYDKxGGSqCBBD8=;
        b=ggzpwn+Xhv15rhiw39Ce0g1vZanHceMST5NUofripOHBGzUAXLGf5dkNhkXICQwTk4
         OPf2FPWPSDHrEhAWXyLe4G1eW+I9lBGdkvAA0g9TMvqal4b9hvkwKf5RqUB1Hk6P9VDl
         nMaQsraHHucEfHMEXGnuVh0iQF+0BiVegMNEVDr6jGXRbCST6aa1cIsousAzye/EWaSr
         JJuM2CCfEd1t/p4pn9G2C0RDb2i3lBmsG8WIC1iAvkQheeRLgK2ZyZILmAh816xwS6eL
         61ijqQ0isA5SLmoDSya4KxAUmYuGhP4FZSHb3M4RRKibNPpnhPG6H8IQCQ2a/fn+Dp/+
         1JsA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from
         :organization:message-id:date:user-agent:mime-version:in-reply-to
         :content-language:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hyyc93OTy8Ay21UspMH9sB8pJ5OV+HYDKxGGSqCBBD8=;
        b=OvGP5ttiG+n6aegbnfY3+oL41YsLVqsARJwS6g2yzuGUx31PupUJXf3Elxcm8NowRO
         dUdadRGZRUTFXXW6e5PK+mVQ56jEcPcfhMgUk0mDBVoAF0Fyhqc+OQxObq61ukCCDNAv
         nV+Nn39cJ3/ew2OGCoXhnt0Hxm4l9olUkNL5dYhrl5LpjOizIX45cpevB5PBRCJk5OTr
         uYcDQchJroidoOyd+N6X4/dCdKvcqYOSpx6acTS64+6iOcTlUJCrXKBEzNnq8Zgzc9MM
         zaUBTSNWWjpJX7EgNpETzEsHzB/XL8+CaqM2wCjflzDa+sY7AtXmcAqEOIIpS75uucz7
         bQqw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuYpDYMirRUDcQQB8OXQcQcrxp7reOCloh05NSBu/YizV9MwCo62
	L1ZHcGG+WGynJ5fQKWz4qMY=
X-Google-Smtp-Source: APiQypKnob9I5bcHYwFW32jP1LBxknPwyLjD6At8pRb2OvBnMevetXf+U82UT9tXZ+n+iAMnZfoOzg==
X-Received: by 2002:a9d:7490:: with SMTP id t16mr1500367otk.48.1586893088965;
        Tue, 14 Apr 2020 12:38:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:3b23:: with SMTP id z32ls1053831otb.1.gmail; Tue, 14 Apr
 2020 12:38:08 -0700 (PDT)
X-Received: by 2002:a05:6830:105:: with SMTP id i5mr20163238otp.185.1586893088544;
        Tue, 14 Apr 2020 12:38:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1586893088; cv=none;
        d=google.com; s=arc-20160816;
        b=h7pgN7scgMdsC5L1eXkBVfrfFXM3kLCIQsiNJ5XudHSm5jbtH0W7cs4YGpZrvpHein
         YzcCEoC0QsFZE1EcnZ3a5Fl/o9G4FaI9rUt6aXkDW7UMaeoRVGU91Otkepr1DQUQaO0Y
         s9H5brxWPExL/wnqAwSasckZ4fmIIhqRIizd3cWzIcVyn0NdgtAjAjI4+ywtU1wKRF2x
         ub12Hcvt09/7ZJg++Zn0I58BrhVDV3QMh/C2Y/MteFhBUdgeAMMFdIJEL2J2agm552Lt
         WITU/C/fwy1nRgQK2yI5lEbgszEhvAhF7ZGfFt6Bm5x0LdvpqF5CvGozxDMgmo7oqTC5
         x7lg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:organization:from:references:cc:to
         :subject:dkim-signature;
        bh=K7rEujuH9mCHHkQNQF3bIC7vs8ss/qE9yTiJvgoWENY=;
        b=pR1vcqa6laPNfuoLOGTwTlN0s/H0s2f3dkwTUeeW+XXjGIHgcYS43zpTH1jV5R1o6M
         vxpyVbServC0u7ckWEsmHEC0HoB1wNhukIbfJHvEr+J3I/m82NP3VYgiwUQb4Wm+omWe
         9ZECtkcSHvf0dDd/KmYgDt2zUlInzzT6VIs6nuiwA9xjPnAwSCAFPdVY6fO6ozITArHS
         QcHU02IIqTxZh8iXMitdgkftYxkfDupSFju2hVjynEFdlS70oOf4+6qtNTaZfivwdo1e
         Wy7h9N1EkEiU720ruji+3T+SgeolVFNxgptwwq59/DhECe8s/Uf1NzTDIEQEzlWsNmQ/
         UtLA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Y4Qcwph2;
       spf=pass (google.com: domain of longman@redhat.com designates 207.211.31.81 as permitted sender) smtp.mailfrom=longman@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-1.mimecast.com (us-smtp-1.mimecast.com. [207.211.31.81])
        by gmr-mx.google.com with ESMTPS id z14si730773oid.1.2020.04.14.12.38.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 14 Apr 2020 12:38:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of longman@redhat.com designates 207.211.31.81 as permitted sender) client-ip=207.211.31.81;
Received: from mimecast-mx01.redhat.com (mimecast-mx01.redhat.com
 [209.132.183.4]) (Using TLS) by relay.mimecast.com with ESMTP id
 us-mta-139-BEtuMjG3PL-f8LyKeyu6gQ-1; Tue, 14 Apr 2020 15:38:03 -0400
X-MC-Unique: BEtuMjG3PL-f8LyKeyu6gQ-1
Received: from smtp.corp.redhat.com (int-mx07.intmail.prod.int.phx2.redhat.com [10.5.11.22])
	(using TLSv1.2 with cipher AECDH-AES256-SHA (256/256 bits))
	(No client certificate requested)
	by mimecast-mx01.redhat.com (Postfix) with ESMTPS id 7A5A58017F3;
	Tue, 14 Apr 2020 19:37:58 +0000 (UTC)
Received: from llong.remote.csb (ovpn-118-173.rdu2.redhat.com [10.10.118.173])
	by smtp.corp.redhat.com (Postfix) with ESMTP id 0277F100E7E3;
	Tue, 14 Apr 2020 19:37:51 +0000 (UTC)
Subject: Re: [PATCH v2 2/2] crypto: Remove unnecessary memzero_explicit()
To: =?UTF-8?Q?Michal_Such=c3=a1nek?= <msuchanek@suse.de>
Cc: Christophe Leroy <christophe.leroy@c-s.fr>,
 Andrew Morton <akpm@linux-foundation.org>,
 David Howells <dhowells@redhat.com>,
 Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>,
 James Morris <jmorris@namei.org>, "Serge E. Hallyn" <serge@hallyn.com>,
 Linus Torvalds <torvalds@linux-foundation.org>, Joe Perches
 <joe@perches.com>, Matthew Wilcox <willy@infradead.org>,
 David Rientjes <rientjes@google.com>, linux-mm@kvack.org,
 keyrings@vger.kernel.org, linux-kernel@vger.kernel.org, x86@kernel.org,
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
References: <20200413211550.8307-1-longman@redhat.com>
 <20200413222846.24240-1-longman@redhat.com>
 <eca85e0b-0af3-c43a-31e4-bd5c3f519798@c-s.fr>
 <e194a51f-a5e5-a557-c008-b08cac558572@redhat.com>
 <20200414191601.GZ25468@kitsune.suse.cz>
From: Waiman Long <longman@redhat.com>
Organization: Red Hat
Message-ID: <578fe9b6-1ccd-2698-60aa-96c3f2dd2c31@redhat.com>
Date: Tue, 14 Apr 2020 15:37:51 -0400
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.7.2
MIME-Version: 1.0
In-Reply-To: <20200414191601.GZ25468@kitsune.suse.cz>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Scanned-By: MIMEDefang 2.84 on 10.5.11.22
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: longman@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=Y4Qcwph2;
       spf=pass (google.com: domain of longman@redhat.com designates
 207.211.31.81 as permitted sender) smtp.mailfrom=longman@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
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

On 4/14/20 3:16 PM, Michal Such=C3=A1nek wrote:
> On Tue, Apr 14, 2020 at 12:24:36PM -0400, Waiman Long wrote:
>> On 4/14/20 2:08 AM, Christophe Leroy wrote:
>>>
>>> Le 14/04/2020 =C3=A0 00:28, Waiman Long a =C3=A9crit=C2=A0:
>>>> Since kfree_sensitive() will do an implicit memzero_explicit(), there
>>>> is no need to call memzero_explicit() before it. Eliminate those
>>>> memzero_explicit() and simplify the call sites. For better correctness=
,
>>>> the setting of keylen is also moved down after the key pointer check.
>>>>
>>>> Signed-off-by: Waiman Long <longman@redhat.com>
>>>> ---
>>>> =C2=A0 .../allwinner/sun8i-ce/sun8i-ce-cipher.c=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0 | 19 +++++-------------
>>>> =C2=A0 .../allwinner/sun8i-ss/sun8i-ss-cipher.c=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0 | 20 +++++--------------
>>>> =C2=A0 drivers/crypto/amlogic/amlogic-gxl-cipher.c=C2=A0=C2=A0 | 12 ++=
+--------
>>>> =C2=A0 drivers/crypto/inside-secure/safexcel_hash.c=C2=A0 |=C2=A0 3 +-=
-
>>>> =C2=A0 4 files changed, 14 insertions(+), 40 deletions(-)
>>>>
>>>> diff --git a/drivers/crypto/allwinner/sun8i-ce/sun8i-ce-cipher.c
>>>> b/drivers/crypto/allwinner/sun8i-ce/sun8i-ce-cipher.c
>>>> index aa4e8fdc2b32..8358fac98719 100644
>>>> --- a/drivers/crypto/allwinner/sun8i-ce/sun8i-ce-cipher.c
>>>> +++ b/drivers/crypto/allwinner/sun8i-ce/sun8i-ce-cipher.c
>>>> @@ -366,10 +366,7 @@ void sun8i_ce_cipher_exit(struct crypto_tfm *tfm)
>>>> =C2=A0 {
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 struct sun8i_cipher_tfm_ctx *op =3D cry=
pto_tfm_ctx(tfm);
>>>> =C2=A0 -=C2=A0=C2=A0=C2=A0 if (op->key) {
>>>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 memzero_explicit(op->key, =
op->keylen);
>>>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 kfree(op->key);
>>>> -=C2=A0=C2=A0=C2=A0 }
>>>> +=C2=A0=C2=A0=C2=A0 kfree_sensitive(op->key);
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 crypto_free_sync_skcipher(op->fallback_=
tfm);
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pm_runtime_put_sync_suspend(op->ce->dev=
);
>>>> =C2=A0 }
>>>> @@ -391,14 +388,11 @@ int sun8i_ce_aes_setkey(struct crypto_skcipher
>>>> *tfm, const u8 *key,
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 dev_dbg(ce->dev=
, "ERROR: Invalid keylen %u\n", keylen);
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return -EINVAL;
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 }
>>>> -=C2=A0=C2=A0=C2=A0 if (op->key) {
>>>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 memzero_explicit(op->key, =
op->keylen);
>>>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 kfree(op->key);
>>>> -=C2=A0=C2=A0=C2=A0 }
>>>> -=C2=A0=C2=A0=C2=A0 op->keylen =3D keylen;
>>>> +=C2=A0=C2=A0=C2=A0 kfree_sensitive(op->key);
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 op->key =3D kmemdup(key, keylen, GFP_KE=
RNEL | GFP_DMA);
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (!op->key)
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return -ENOMEM;
>>>> +=C2=A0=C2=A0=C2=A0 op->keylen =3D keylen;
>>> Does it matter at all to ensure op->keylen is not set when of->key is
>>> NULL ? I'm not sure.
>>>
>>> But if it does, then op->keylen should be set to 0 when freeing op->key=
.=20
>> My thinking is that if memory allocation fails, we just don't touch
>> anything and return an error code. I will not explicitly set keylen to 0
>> in this case unless it is specified in the API documentation.
> You already freed the key by now so not touching anything is not
> possible. The key is set to NULL on allocation failure so setting keylen
> to 0 should be redundant. However, setting keylen to 0 is consisent with
> not having a key, and it avoids the possibility of leaking the length
> later should that ever cause any problem.

OK, I can change it to clear the key length when the allocation failed
which isn't likely.

Cheers,
Longman


--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/578fe9b6-1ccd-2698-60aa-96c3f2dd2c31%40redhat.com.
