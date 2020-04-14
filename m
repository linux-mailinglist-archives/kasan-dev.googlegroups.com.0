Return-Path: <kasan-dev+bncBAABB6EX3D2AKGQERX5LITY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 159AB1A8A8B
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Apr 2020 21:16:09 +0200 (CEST)
Received: by mail-wr1-x43b.google.com with SMTP id g6sf9230115wru.8
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Apr 2020 12:16:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1586891768; cv=pass;
        d=google.com; s=arc-20160816;
        b=IGnmKVSUmssUTjX9c4rsBlD3ovZ2WVjzr8iJxc3FVHqUeiY4UJBf+BByuNHDPVyCI2
         NFVf/GEqbHEz3WnC0i+OFvstUiqFVw0lArJWRs8Mil34fJhAAhc/Bjmca2RSXBR6XuAl
         sUbqp9WG6MYpZqU45511xZbyJi7ivu6iPykiLAHLdi4kNTChWWe4GAV0SG5uDDv18z+t
         M/S8h2Bzfan4GOoNi1OKuy3N2m2QYbPY3nIrij+O7GbRICqUFkDAeg6xystnpnsFRYtz
         u1E70lRAYHIRAnO+mV9didsbQYmTtMkm5FOGp/zAQyGJxoI9faGi+x2xdMSrUxD3aloM
         r5rA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=wRcn/2/29LnqcM0h56t5iJ7Jim1Onip52btKS3qPErg=;
        b=0/TAIEo36I0jlPKRbrXwBvp2Q4EYwiXw3N0Vd0nKdB5NpjySJLt4Kt6Is6ilJbQJ6t
         lv4HvMt33YQQ8TFJSUbFMRieGn1uChxl+jdtvzyE8/lnS6UaQhczBlKBQFy0leZDhJ1z
         u04KTlHYk8wrBBkz7hBQoDyAZvmIsB9FRYr1hQWRSg2AIQ4GJ8sR3RGgl69HqViOwP9m
         3SDvpIGpBuCwUA9PeZzsPxGUmdelicgPuoyTqXbl5zVsWwTyf8Q+kaQa66VPfu+EQEok
         dzGS7LgSPwKW+AdCR0S4PIXWDVq+pJpDWZgyZ/pdrtXGuD9vRrsU5YmLOQAoe223w90V
         pj9g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of msuchanek@suse.de designates 195.135.220.15 as permitted sender) smtp.mailfrom=msuchanek@suse.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wRcn/2/29LnqcM0h56t5iJ7Jim1Onip52btKS3qPErg=;
        b=O2IrqdYJCYPwgzjYtUMVJpmpjGNoBKfl3TZ2+pbX+oVaAoMg52EbSME/7DiAUGkecW
         gR39aaon4KQYU31MwroQLYLnxSarSUHnNUyYFXfCMzRSBJ4Z5Kuoxcg0gL1rnR0pohtw
         FxnzSeIckElloO+V66/iRZsO22kR2DUC/4zx4lr3CMW4UI2xuADe3+Ofpatd7uhdna/A
         dyuIjU9N8Ldc8ICI12EXFwMuHQkD441kIK8I92EWd/q8agojCB7uMTw0UoBNQqQZJtSY
         vBdBleTJz/jGtFCZUChet+YFYMurlb9+ayn5Lwu6EDer/L60DTK/sg5VcxxAfHuDkJMA
         5LeQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wRcn/2/29LnqcM0h56t5iJ7Jim1Onip52btKS3qPErg=;
        b=W9Q+92Y9bA67IG5uC687tsD1KUrgqpgnTcdUnNFnG+NsUsbN0+IKyWR2OXSZT9Wy8X
         ksTBYlYNSKBJN/eAitkxy+jvSiK4fedu7fB9h3TgA3EQcV4J8J0FWY4F6MkMZtHI5Y6P
         5yhFPcfqvMpmTQC9xMGl/eVJOrowCYnyT0UzOYSlyXVvcoE37pv9UR7bF49DULnw37K/
         U4W4mrvoATh5Mg488+umamuJS31zGocv9WHyK8m5U0FZDOsQr3CGcir5TOHmokDfkV7o
         bMOvhyXxkSevL0SW5Az7suYUifNhiv7Ln29J3CyC9VEYINi072XZA1cAj/vLM49nq52D
         0hug==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuZRNFt9xxfN2FMPWAaQGkLl466LkIs9WYOHv8io5myB1bL+XSq6
	lZ1cpPbHyFQAV7CSdzRjK8U=
X-Google-Smtp-Source: APiQypJPEppcwvTCWUc3GqGXa/32YdRgv17VUiJMFE8SkX1CTxhBVGT2lc6CLnAl4hGhkxZIK9ffqQ==
X-Received: by 2002:a05:600c:2194:: with SMTP id e20mr1323154wme.22.1586891768761;
        Tue, 14 Apr 2020 12:16:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f5cc:: with SMTP id k12ls3996626wrp.6.gmail; Tue, 14 Apr
 2020 12:16:08 -0700 (PDT)
X-Received: by 2002:adf:bb0d:: with SMTP id r13mr26934703wrg.251.1586891768315;
        Tue, 14 Apr 2020 12:16:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1586891768; cv=none;
        d=google.com; s=arc-20160816;
        b=wKv5HCRUfeOOs/Ms24mM7Q5fR7L4d1c4LFyXqKNM/AYn1/TFxC2hxLkflQc9n6JLpO
         dETsRuoG+gLGwaqTF9l+rrnfY0z55eoVKUSMekKXkJAyKExPLMIUnHiYGUFx+GpCUzIh
         5pwbHhJG36JRisP9PEZ4iZxP39o5ncTOK1zew96/JgUtxtaWWWNrAIMbsxblSdnFzrp4
         OTjoPMYitAyS5xY+/UYDTks11lVWujSZ2cSVfMIB3hQa+gZZGWKwDvS/SfnFQfyeAvSe
         vhAbA4QKtnd3SU9KvDkUZLr9OooJzselc/4pzYoLjNv/386L1jzBs+V9URq2JuFyFl6x
         AwNg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date;
        bh=wq2D8kMLTqBEeRfH2QA/6ol1yvpwP7xIHEUI7U6lC30=;
        b=HkXQN3IInKGhEovIEM2FE6dFuRUH7Dcp0zfkmtI7qbIYnPSzGC0RudtgPYP5V14g9V
         3mCvdJE5ACC+28Hsk1JyIcvMcvgoCOvUZ7YBowwL7TFfnClU0Rt1i/atz1g7VWgZaGNa
         XiFMyxoYLAe393hDzu2P2lBfpbUgM7QbSAqjB3ZaSoa46YdHI7tzhxtQQ872EhS/Hd5j
         pTDf9Q/+qQV26HPVfDwrrEC3t6xmD0Q43lt5tmmixl/mxCb7qreskyLGEowcVAFeaAhb
         ce97FIL17b4xjST9LEyhIE9PxahTwfXzaz3YQJMJyRvRAC9Gi6cF/DdrSQYVQzxTI704
         HSJQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of msuchanek@suse.de designates 195.135.220.15 as permitted sender) smtp.mailfrom=msuchanek@suse.de
Received: from mx2.suse.de (mx2.suse.de. [195.135.220.15])
        by gmr-mx.google.com with ESMTPS id z84si766874wmc.2.2020.04.14.12.16.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 14 Apr 2020 12:16:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of msuchanek@suse.de designates 195.135.220.15 as permitted sender) client-ip=195.135.220.15;
X-Virus-Scanned: by amavisd-new at test-mx.suse.de
Received: from relay2.suse.de (unknown [195.135.220.254])
	by mx2.suse.de (Postfix) with ESMTP id 63506AC2C;
	Tue, 14 Apr 2020 19:16:04 +0000 (UTC)
Date: Tue, 14 Apr 2020 21:16:01 +0200
From: Michal =?iso-8859-1?Q?Such=E1nek?= <msuchanek@suse.de>
To: Waiman Long <longman@redhat.com>
Cc: Christophe Leroy <christophe.leroy@c-s.fr>,
	Andrew Morton <akpm@linux-foundation.org>,
	David Howells <dhowells@redhat.com>,
	Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>,
	James Morris <jmorris@namei.org>,
	"Serge E. Hallyn" <serge@hallyn.com>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	Joe Perches <joe@perches.com>, Matthew Wilcox <willy@infradead.org>,
	David Rientjes <rientjes@google.com>, linux-mm@kvack.org,
	keyrings@vger.kernel.org, linux-kernel@vger.kernel.org,
	x86@kernel.org, linux-crypto@vger.kernel.org,
	linux-s390@vger.kernel.org, linux-pm@vger.kernel.org,
	linux-stm32@st-md-mailman.stormreply.com,
	linux-arm-kernel@lists.infradead.org,
	linux-amlogic@lists.infradead.org,
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
Subject: Re: [PATCH v2 2/2] crypto: Remove unnecessary memzero_explicit()
Message-ID: <20200414191601.GZ25468@kitsune.suse.cz>
References: <20200413211550.8307-1-longman@redhat.com>
 <20200413222846.24240-1-longman@redhat.com>
 <eca85e0b-0af3-c43a-31e4-bd5c3f519798@c-s.fr>
 <e194a51f-a5e5-a557-c008-b08cac558572@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <e194a51f-a5e5-a557-c008-b08cac558572@redhat.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: msuchanek@suse.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of msuchanek@suse.de designates 195.135.220.15 as
 permitted sender) smtp.mailfrom=msuchanek@suse.de
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

On Tue, Apr 14, 2020 at 12:24:36PM -0400, Waiman Long wrote:
> On 4/14/20 2:08 AM, Christophe Leroy wrote:
> >
> >
> > Le 14/04/2020 =C3=A0 00:28, Waiman Long a =C3=A9crit=C2=A0:
> >> Since kfree_sensitive() will do an implicit memzero_explicit(), there
> >> is no need to call memzero_explicit() before it. Eliminate those
> >> memzero_explicit() and simplify the call sites. For better correctness=
,
> >> the setting of keylen is also moved down after the key pointer check.
> >>
> >> Signed-off-by: Waiman Long <longman@redhat.com>
> >> ---
> >> =C2=A0 .../allwinner/sun8i-ce/sun8i-ce-cipher.c=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0 | 19 +++++-------------
> >> =C2=A0 .../allwinner/sun8i-ss/sun8i-ss-cipher.c=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0 | 20 +++++--------------
> >> =C2=A0 drivers/crypto/amlogic/amlogic-gxl-cipher.c=C2=A0=C2=A0 | 12 ++=
+--------
> >> =C2=A0 drivers/crypto/inside-secure/safexcel_hash.c=C2=A0 |=C2=A0 3 +-=
-
> >> =C2=A0 4 files changed, 14 insertions(+), 40 deletions(-)
> >>
> >> diff --git a/drivers/crypto/allwinner/sun8i-ce/sun8i-ce-cipher.c
> >> b/drivers/crypto/allwinner/sun8i-ce/sun8i-ce-cipher.c
> >> index aa4e8fdc2b32..8358fac98719 100644
> >> --- a/drivers/crypto/allwinner/sun8i-ce/sun8i-ce-cipher.c
> >> +++ b/drivers/crypto/allwinner/sun8i-ce/sun8i-ce-cipher.c
> >> @@ -366,10 +366,7 @@ void sun8i_ce_cipher_exit(struct crypto_tfm *tfm)
> >> =C2=A0 {
> >> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 struct sun8i_cipher_tfm_ctx *op =3D cry=
pto_tfm_ctx(tfm);
> >> =C2=A0 -=C2=A0=C2=A0=C2=A0 if (op->key) {
> >> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 memzero_explicit(op->key, =
op->keylen);
> >> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 kfree(op->key);
> >> -=C2=A0=C2=A0=C2=A0 }
> >> +=C2=A0=C2=A0=C2=A0 kfree_sensitive(op->key);
> >> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 crypto_free_sync_skcipher(op->fallback_=
tfm);
> >> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pm_runtime_put_sync_suspend(op->ce->dev=
);
> >> =C2=A0 }
> >> @@ -391,14 +388,11 @@ int sun8i_ce_aes_setkey(struct crypto_skcipher
> >> *tfm, const u8 *key,
> >> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 dev_dbg(ce->dev=
, "ERROR: Invalid keylen %u\n", keylen);
> >> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return -EINVAL;
> >> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 }
> >> -=C2=A0=C2=A0=C2=A0 if (op->key) {
> >> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 memzero_explicit(op->key, =
op->keylen);
> >> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 kfree(op->key);
> >> -=C2=A0=C2=A0=C2=A0 }
> >> -=C2=A0=C2=A0=C2=A0 op->keylen =3D keylen;
> >> +=C2=A0=C2=A0=C2=A0 kfree_sensitive(op->key);
> >> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 op->key =3D kmemdup(key, keylen, GFP_KE=
RNEL | GFP_DMA);
> >> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (!op->key)
> >> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return -ENOMEM;
> >> +=C2=A0=C2=A0=C2=A0 op->keylen =3D keylen;
> >
> > Does it matter at all to ensure op->keylen is not set when of->key is
> > NULL ? I'm not sure.
> >
> > But if it does, then op->keylen should be set to 0 when freeing op->key=
.=20
>=20
> My thinking is that if memory allocation fails, we just don't touch
> anything and return an error code. I will not explicitly set keylen to 0
> in this case unless it is specified in the API documentation.
You already freed the key by now so not touching anything is not
possible. The key is set to NULL on allocation failure so setting keylen
to 0 should be redundant. However, setting keylen to 0 is consisent with
not having a key, and it avoids the possibility of leaking the length
later should that ever cause any problem.

Thanks

Michal

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20200414191601.GZ25468%40kitsune.suse.cz.
