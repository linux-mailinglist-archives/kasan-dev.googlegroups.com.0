Return-Path: <kasan-dev+bncBCPILY4NUAFBBXWH272AKGQEDKZDW3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33b.google.com (mail-ot1-x33b.google.com [IPv6:2607:f8b0:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 785D11A849C
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Apr 2020 18:25:03 +0200 (CEST)
Received: by mail-ot1-x33b.google.com with SMTP id a21sf425000oto.15
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Apr 2020 09:25:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1586881502; cv=pass;
        d=google.com; s=arc-20160816;
        b=xp3NomjuCcHy6nrJ7Klt3yKN6Sw+0lem8VeMb69sGFBYO7dyTd5OGe3h0CIvhosbZk
         J6LJG7b/O3XjH+tZdTYg/uamVlvfM8VuxZIBL/Hj8RJzuF/wGI7HMGG04K5WQJPhCXMK
         AvmkCr8mR31OEABarlz/3Nxlro/HmYblREZNjdICuBY99rlfJXYL1sVEeX+Wjmxn1TyO
         yPY/9gjS+7snAbuNsSV9xbUJOx/Lt7bMvs4IHq6F/ohnY0Ej9zsmt3Qb/pwDmCEJ+xwz
         GTqeae+n4K3NRxUWTufgb1tOBJEjW6Dr5b83FfpVoSB783gZIRg15ruS1rAlAWZs/UXq
         tgBA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:organization:from:references:cc:to:subject:sender
         :dkim-signature;
        bh=FH+RFvqaQ2VCwSZ5b5ZrG/4EPR4cQ5lMACYkryNTWGU=;
        b=FUgLPqPp2tI9nT66ee2OFhdjR41kVc8NPQrlnLZJ1OiTVBda86Cv4/3Qq2VXbJDLiO
         OdJ9dIH1wjMmbIkfPgoW77Jx5FZbwf0D/kEk8g95FgVDdza2EjtO5vxTygCE6Hth5ryz
         kOgaIjOZZ9QMnQs92sh9VMUUEvJAYf+DMQQ6TRowq9yNJoyyuRKxQebzH633gFDKF9Wv
         eoludwLqsW0fsIDDcrA1XzPP2Os6mdEMPlAEvXmNBnI4nAmVleDFJCgIdJwyh6vkUMrr
         RjaYkDmsDawb/dlYmFDsBGeVPn+FV0GRjSf4S6JTSMAqGzPjpKsM/U9W0R8VLCcmSebO
         cL1Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=NsgcQPq0;
       spf=pass (google.com: domain of longman@redhat.com designates 207.211.31.120 as permitted sender) smtp.mailfrom=longman@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:organization:message-id:date
         :user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=FH+RFvqaQ2VCwSZ5b5ZrG/4EPR4cQ5lMACYkryNTWGU=;
        b=W6nLf5VW59lP99TgP672hbF3XtETJs2tdv66wCDAwy7kDvJ4HKRpcgliVeEmWShScx
         7o8X0xVh61vuPfLYGnoG7e/DiGik8z3dg280PLWxKTAywrq9HPfSW4KuQnVfzIZztYmA
         3gL77Y2trQixJTOuqIgSDcXhlvyXJ/fbJtnSqHg0bRQ975NfMJxlWbZnnZETGvXMa1In
         JU6QwHCsB19s2jmSFzIaEb45/QaVPexsYIMvk3+E/yqOqeE0/Z9uUI9VMwynUt//B+NO
         TOnCcfUVD/LMPlHerR7rmVfKxnxYfGpAA6e9kMEqOM97fbQwSF8g8OpgfVRcFfg57BdJ
         7yyA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from
         :organization:message-id:date:user-agent:mime-version:in-reply-to
         :content-language:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FH+RFvqaQ2VCwSZ5b5ZrG/4EPR4cQ5lMACYkryNTWGU=;
        b=A+H5z5RTZ4WbSKMG6kJTnXeLZhWSJ6Rva45E4LX/M+7SG0cSUIDygcoMxzQBUjfBbS
         nAF6+pfCr654YZ+wnKAkoeBjhTA+5Zia90Bn7ZxkGHhn48AFPYbaxE6Ot6YxJg9uUUyJ
         ktcRpK+YLHD/TnR6zaPOQ+9PZPxt9AEb71j8aJvuqo3QpvtgMF8UVzEQRWaOq+4d/Xg+
         wETWkry5jsJhzVFdjPuD/hHdD5lYMCYxR0YvmHFDaJQfsszpL/xm+4P7dJAnkbCBs/Of
         qgwn8/qRHbzjtZfJBV16Q64qhNEgUemuj6En8Dgt4JbN1HKoQ8t5vEXlkyEK304YUZEo
         p5Cg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuYdHHKVC392bjuOT0AAUbk6JfGAJX2qCuyHx327kDXrr4dStWDP
	ZJ/1YafS12S8BvP9c21dbQ4=
X-Google-Smtp-Source: APiQypJa/j8GFG9dlGFF8hU/aIMXqVFwXIo3E6sktQGKMJmohKca6ytyJLjwXtyE16u8f+97+cPGpQ==
X-Received: by 2002:a05:6830:1453:: with SMTP id w19mr2475671otp.230.1586881502155;
        Tue, 14 Apr 2020 09:25:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:3b23:: with SMTP id z32ls913829otb.1.gmail; Tue, 14 Apr
 2020 09:25:01 -0700 (PDT)
X-Received: by 2002:a9d:2056:: with SMTP id n80mr20117902ota.281.1586881501755;
        Tue, 14 Apr 2020 09:25:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1586881501; cv=none;
        d=google.com; s=arc-20160816;
        b=mSRAlw0vpOe4tSneKrXSfH6StWn3cqkc9qTOEgBamjSFWASQp+/HrNQuah69fKyWlT
         HbXtJgaPslZDQRoNU6PI4ZXmhHkooXpKDX0D6ILG6KlfXCX63ZH20Vdi/ZdA2CZyk9RP
         cZiijTZvas6ZOi8P3KEMcX9TSqxSMfJgWTCWgj62UIs1+Iu4I7uFwwHtTFDjWhxY+s7S
         hQpNzj8JSumNRh3q82eDY08o/1QkoRHeBF29ahbBI3iHrEenz3NrUdC2Cog7+Ki1tqPR
         Qr3ZWE2oGupf7BkyNHLw8soyNAQFa4bHUEHGqsGEOXx9ebTZqp0SGnK/qmRpjX2xK4xs
         wTxw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:organization:from:references:cc:to
         :subject:dkim-signature;
        bh=yW8t58m2bp1NhazlqC7/k8J+nPWsrZBYDWUsjTyk2qQ=;
        b=pLzNSaURJvduk3jjzijJNR4ERB/Li/Z5To/dURkWUwEYgdxB2yoq54FADvaHeyTrBe
         57PKnuG83YyVpYeTaVNZsZ2E9keO1Aya9BSh4rV8zJKBVdUtTIZsyK6SjeIyGc3llBQz
         ju2Pv7mhCAtd1G71pOvUv6XM4UaF5rlblm5aGRNxc9bdxo9fEyYsgBuYW6WuK0RvSJTb
         5XCqMrMz3kLpf0jp4mLUgoErHM1oFikMxOSqysKxQNcVhd3C66R2BnOocyXUBsQJqVGI
         FyWPbohbdvG9PrhYqWMJEI8GIHX/zayMC4ZbYs4Pqz/E2zSQROe25PEBsxcMK/7Ywk2Q
         tXiA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=NsgcQPq0;
       spf=pass (google.com: domain of longman@redhat.com designates 207.211.31.120 as permitted sender) smtp.mailfrom=longman@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-1.mimecast.com (us-smtp-delivery-1.mimecast.com. [207.211.31.120])
        by gmr-mx.google.com with ESMTPS id f7si792366oti.0.2020.04.14.09.25.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 14 Apr 2020 09:25:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of longman@redhat.com designates 207.211.31.120 as permitted sender) client-ip=207.211.31.120;
Received: from mimecast-mx01.redhat.com (mimecast-mx01.redhat.com
 [209.132.183.4]) (Using TLS) by relay.mimecast.com with ESMTP id
 us-mta-87-m_CJjLwlPvyXxruKyZ4cKA-1; Tue, 14 Apr 2020 12:24:56 -0400
X-MC-Unique: m_CJjLwlPvyXxruKyZ4cKA-1
Received: from smtp.corp.redhat.com (int-mx05.intmail.prod.int.phx2.redhat.com [10.5.11.15])
	(using TLSv1.2 with cipher AECDH-AES256-SHA (256/256 bits))
	(No client certificate requested)
	by mimecast-mx01.redhat.com (Postfix) with ESMTPS id 12123107ACC4;
	Tue, 14 Apr 2020 16:24:50 +0000 (UTC)
Received: from llong.remote.csb (ovpn-118-173.rdu2.redhat.com [10.10.118.173])
	by smtp.corp.redhat.com (Postfix) with ESMTP id 0E02D118DEE;
	Tue, 14 Apr 2020 16:24:36 +0000 (UTC)
Subject: Re: [PATCH v2 2/2] crypto: Remove unnecessary memzero_explicit()
To: Christophe Leroy <christophe.leroy@c-s.fr>,
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
 <eca85e0b-0af3-c43a-31e4-bd5c3f519798@c-s.fr>
From: Waiman Long <longman@redhat.com>
Organization: Red Hat
Message-ID: <e194a51f-a5e5-a557-c008-b08cac558572@redhat.com>
Date: Tue, 14 Apr 2020 12:24:36 -0400
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.7.2
MIME-Version: 1.0
In-Reply-To: <eca85e0b-0af3-c43a-31e4-bd5c3f519798@c-s.fr>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Scanned-By: MIMEDefang 2.79 on 10.5.11.15
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: longman@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=NsgcQPq0;
       spf=pass (google.com: domain of longman@redhat.com designates
 207.211.31.120 as permitted sender) smtp.mailfrom=longman@redhat.com;
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

On 4/14/20 2:08 AM, Christophe Leroy wrote:
>
>
> Le 14/04/2020 =C3=A0 00:28, Waiman Long a =C3=A9crit=C2=A0:
>> Since kfree_sensitive() will do an implicit memzero_explicit(), there
>> is no need to call memzero_explicit() before it. Eliminate those
>> memzero_explicit() and simplify the call sites. For better correctness,
>> the setting of keylen is also moved down after the key pointer check.
>>
>> Signed-off-by: Waiman Long <longman@redhat.com>
>> ---
>> =C2=A0 .../allwinner/sun8i-ce/sun8i-ce-cipher.c=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0 | 19 +++++-------------
>> =C2=A0 .../allwinner/sun8i-ss/sun8i-ss-cipher.c=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0 | 20 +++++--------------
>> =C2=A0 drivers/crypto/amlogic/amlogic-gxl-cipher.c=C2=A0=C2=A0 | 12 +++-=
-------
>> =C2=A0 drivers/crypto/inside-secure/safexcel_hash.c=C2=A0 |=C2=A0 3 +--
>> =C2=A0 4 files changed, 14 insertions(+), 40 deletions(-)
>>
>> diff --git a/drivers/crypto/allwinner/sun8i-ce/sun8i-ce-cipher.c
>> b/drivers/crypto/allwinner/sun8i-ce/sun8i-ce-cipher.c
>> index aa4e8fdc2b32..8358fac98719 100644
>> --- a/drivers/crypto/allwinner/sun8i-ce/sun8i-ce-cipher.c
>> +++ b/drivers/crypto/allwinner/sun8i-ce/sun8i-ce-cipher.c
>> @@ -366,10 +366,7 @@ void sun8i_ce_cipher_exit(struct crypto_tfm *tfm)
>> =C2=A0 {
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 struct sun8i_cipher_tfm_ctx *op =3D crypt=
o_tfm_ctx(tfm);
>> =C2=A0 -=C2=A0=C2=A0=C2=A0 if (op->key) {
>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 memzero_explicit(op->key, op=
->keylen);
>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 kfree(op->key);
>> -=C2=A0=C2=A0=C2=A0 }
>> +=C2=A0=C2=A0=C2=A0 kfree_sensitive(op->key);
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 crypto_free_sync_skcipher(op->fallback_tf=
m);
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pm_runtime_put_sync_suspend(op->ce->dev);
>> =C2=A0 }
>> @@ -391,14 +388,11 @@ int sun8i_ce_aes_setkey(struct crypto_skcipher
>> *tfm, const u8 *key,
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 dev_dbg(ce->dev, =
"ERROR: Invalid keylen %u\n", keylen);
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return -EINVAL;
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 }
>> -=C2=A0=C2=A0=C2=A0 if (op->key) {
>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 memzero_explicit(op->key, op=
->keylen);
>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 kfree(op->key);
>> -=C2=A0=C2=A0=C2=A0 }
>> -=C2=A0=C2=A0=C2=A0 op->keylen =3D keylen;
>> +=C2=A0=C2=A0=C2=A0 kfree_sensitive(op->key);
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 op->key =3D kmemdup(key, keylen, GFP_KERN=
EL | GFP_DMA);
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (!op->key)
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return -ENOMEM;
>> +=C2=A0=C2=A0=C2=A0 op->keylen =3D keylen;
>
> Does it matter at all to ensure op->keylen is not set when of->key is
> NULL ? I'm not sure.
>
> But if it does, then op->keylen should be set to 0 when freeing op->key.=
=20

My thinking is that if memory allocation fails, we just don't touch
anything and return an error code. I will not explicitly set keylen to 0
in this case unless it is specified in the API documentation.

Cheers,
Longman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/e194a51f-a5e5-a557-c008-b08cac558572%40redhat.com.
