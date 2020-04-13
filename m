Return-Path: <kasan-dev+bncBCPILY4NUAFBBRWP2P2AKGQE2BQH4FQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id B25BE1A6F1D
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Apr 2020 00:29:27 +0200 (CEST)
Received: by mail-pl1-x63b.google.com with SMTP id w3sf8279816plz.15
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Apr 2020 15:29:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1586816966; cv=pass;
        d=google.com; s=arc-20160816;
        b=wM4AGmbOv9c5oqVniMgsVtj0N0bTDXiqIosKXHHiwoFjQ0vIKRwZS/O8T54w3R932C
         c/9y4mk62O4IQOAAmObaPKsKut3nno5fZqsii6UVPBbRmZT4TCUK8WAj6bvL8h+TeqA1
         ADCWPkQJ5ecieSp2+K6XZikfDQfDfjoWbnVP46NuXgrpbU63heek7O97NJQHjxSvr6JE
         6QqCqZVQPrr/i1XzX7tbwGb1CAp9VjTT9KqfoFgP7RxGTz1gMiDmE12Ujy3lDDiOA4cD
         xtFJIT9uXFbn1Hyfi4RdZhMUd/9MYbDRfuhalMJfS1ovQicLWOsKLsnzLVYBnpmlScbI
         XlKw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=+pU1LpUPS6JqOHnanZMJUakOAwpxFB0OIXJwwywsg8Y=;
        b=UlOSha+aaxj7B1MAG7ejLeOnll9DWKugZ+qFwkN7wSNSIWcDSqSEJt8kuDhUCgKF9A
         plfCHurt637akHmBbK2KjLaN6x4sSgAVl4+hA5/zi+sOBX5WdZonRbdtQp/+kFfg+gNb
         RCYQilgqH5dpI5llz3fH7DnGki2bdmfaNpbgiKhN8BXQI0EEFBnbb0ZBg1CgUq1Uzrqe
         g2x2PytfJHbVaQDhv6QcHX8WU3en6gX8e93nWQWQ1sIk+JejeKWDfYBCjX5kaUgZZ81g
         +qlTz7QIsSQICVpMq0m0afF1u3BgPokM8wUjO6zHiQwktCLgEM4XNOPBitJ3XkK1tC7R
         xoaQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=a2qwqlIc;
       spf=pass (google.com: domain of longman@redhat.com designates 207.211.31.81 as permitted sender) smtp.mailfrom=longman@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+pU1LpUPS6JqOHnanZMJUakOAwpxFB0OIXJwwywsg8Y=;
        b=soJAsOeMVXPU21/BXRRgl3oVGBlSXorsQ7vL4tN6mTtwXRjUIa7PTxQA4gwg3j8QvE
         8ZFRL7uCzIfitEfbYSNG0m9d7vYvj9VatgdZubZouUmVm/3wqtWdD0WPuCC+vNVdiuqL
         sLB2ZUceqRS9HexcXVL3MbPoGeUzZwiZ4/CnPY3SDDLTtBCj8LuJu4i8RfMhvRsdOJOx
         6N7Llvlc0S4ftTMcmctb2jPdC4FZQdX2hMTJVdQjHrYuZPwvAnyy0G4upSWwsjoaL3jL
         6osOIa7DJ8QVm7ANQ4PfqY/ANMjpDNZI/+EITOdPR9C7MNNEcwVBk5tlP5vSYUAjdSj1
         vFMg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+pU1LpUPS6JqOHnanZMJUakOAwpxFB0OIXJwwywsg8Y=;
        b=VCynJsqWPKyP2+Kt0UtWcLyvllhFjeYBUq3DGfhcBLxbDcuQoqWkGXJKnXquCS/Jj9
         yMq2yzOIPAgK/Fm01DMtjWaD/dKphyMCRx/n/3Cw4ZxYlBZ8wu7pMmG6UB9xaOMvkTt3
         fmlj77dPraDE+NdwkoleT4wSWa55rT3SvyFr+GXu6Lw/QsmDQWcsz9J4datkIVDZRH5z
         tp/WQiPMsegvrZxWnGCwQbWv2vieBV0UzZhFJ8fcHGEVhiU+YNvUm5pn4CBwBVpN9Xqk
         fsqHWic05bUdGdDIAVQPbDFaQqXxQNRD3rYv+vOWQmmbGhFUs3c8nK+dini7pjrebVs1
         9BhQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuZmMrHdCtbSZ92rdHyJsopJ+kc0rTgS+BWx387/UR5aGD1opefT
	Q4g9a30OhtmVkX+SUVHMZR0=
X-Google-Smtp-Source: APiQypLbTM6+YZ9K3mQ/C8P6g5bhc5kzYcr2DSws5nTfwPHv3eGHDMAMy86jTscJphBzK5yy5YSeGw==
X-Received: by 2002:aa7:969b:: with SMTP id f27mr19296492pfk.116.1586816966197;
        Mon, 13 Apr 2020 15:29:26 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:8488:: with SMTP id c8ls2206492plo.8.gmail; Mon, 13
 Apr 2020 15:29:25 -0700 (PDT)
X-Received: by 2002:a17:902:b618:: with SMTP id b24mr20445331pls.213.1586816965818;
        Mon, 13 Apr 2020 15:29:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1586816965; cv=none;
        d=google.com; s=arc-20160816;
        b=HOqecdwXDnFXsnS5vucn8XhGxxYLvG6ThsU8wU2UGvXSPiIciIZLodaZvNpKPeVZJ4
         aWpa9Y//QV0liDTlVAUVluJob7vlm/OJ/n5g3He8Zng8U13JHdm88blTNASLppebxW5a
         5/V+6f7RtIJNHoeeoKyyRHmYJSZC35MnFL38gSWz7beoQTJTZIdg/Uku5NwM4VJcQq35
         idpkrFJcy8hbgil7scAedcl1571i+w0dn6rXrIchAC3JocEw59sli3OT43r0tZGh2iqi
         UHs9YFMR31KXF0oj8WT9c9Oux8bYPtWbM+doTr2BzKCaFZoPvdfqL3LLO5vYeL4UxUIs
         3Grw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=xENEjcmhPGwc2y5vLor/EJ6DRudCRi6D5WVSWBMRKcI=;
        b=IP2FhZatGHeFyFcsjsTcXm2J7CB8fV0jTzygz1iE6fpxFCEVCFHYVLYz2dHUwttmch
         9k2FgKmcSIPXcNeZDa/WQ9a3rBVnzFrd26LOpxPg97yr/pJjJjUR7FsbZ/Rx4r7pgKPa
         pq6JDlqXcXFBcAGvrDYpa1PmjtFEc9jT04Re15t6RmcOTDlwBt8In+fLbtB97l/24Zao
         3js5QWmQHgN2aqlVpZtZfCNT1I8TUjy8wEWPRBC096v9Gq5XZzoD7ezuoqKQ60x4fP3v
         mrYwWRITM8fpEEPFzNDeKIPwn1Knx776KNdEm8K+WXXdU9QP1i1A6Wy5O3HZqoW1+Vf0
         BF6g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=a2qwqlIc;
       spf=pass (google.com: domain of longman@redhat.com designates 207.211.31.81 as permitted sender) smtp.mailfrom=longman@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-1.mimecast.com (us-smtp-2.mimecast.com. [207.211.31.81])
        by gmr-mx.google.com with ESMTPS id t15si815379pgb.1.2020.04.13.15.29.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 13 Apr 2020 15:29:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of longman@redhat.com designates 207.211.31.81 as permitted sender) client-ip=207.211.31.81;
Received: from mimecast-mx01.redhat.com (mimecast-mx01.redhat.com
 [209.132.183.4]) (Using TLS) by relay.mimecast.com with ESMTP id
 us-mta-285-8AaFvKVINBm7IlQx6B5FDA-1; Mon, 13 Apr 2020 18:29:20 -0400
X-MC-Unique: 8AaFvKVINBm7IlQx6B5FDA-1
Received: from smtp.corp.redhat.com (int-mx07.intmail.prod.int.phx2.redhat.com [10.5.11.22])
	(using TLSv1.2 with cipher AECDH-AES256-SHA (256/256 bits))
	(No client certificate requested)
	by mimecast-mx01.redhat.com (Postfix) with ESMTPS id CC5481005513;
	Mon, 13 Apr 2020 22:29:15 +0000 (UTC)
Received: from llong.com (ovpn-115-28.rdu2.redhat.com [10.10.115.28])
	by smtp.corp.redhat.com (Postfix) with ESMTP id 3589D100164D;
	Mon, 13 Apr 2020 22:29:07 +0000 (UTC)
From: Waiman Long <longman@redhat.com>
To: Andrew Morton <akpm@linux-foundation.org>,
	David Howells <dhowells@redhat.com>,
	Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>,
	James Morris <jmorris@namei.org>,
	"Serge E. Hallyn" <serge@hallyn.com>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	Joe Perches <joe@perches.com>,
	Matthew Wilcox <willy@infradead.org>,
	David Rientjes <rientjes@google.com>
Cc: linux-mm@kvack.org,
	keyrings@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	x86@kernel.org,
	linux-crypto@vger.kernel.org,
	linux-s390@vger.kernel.org,
	linux-pm@vger.kernel.org,
	linux-stm32@st-md-mailman.stormreply.com,
	linux-arm-kernel@lists.infradead.org,
	linux-amlogic@lists.infradead.org,
	linux-mediatek@lists.infradead.org,
	linuxppc-dev@lists.ozlabs.org,
	virtualization@lists.linux-foundation.org,
	netdev@vger.kernel.org,
	intel-wired-lan@lists.osuosl.org,
	linux-ppp@vger.kernel.org,
	wireguard@lists.zx2c4.com,
	linux-wireless@vger.kernel.org,
	devel@driverdev.osuosl.org,
	linux-scsi@vger.kernel.org,
	target-devel@vger.kernel.org,
	linux-btrfs@vger.kernel.org,
	linux-cifs@vger.kernel.org,
	samba-technical@lists.samba.org,
	linux-fscrypt@vger.kernel.org,
	ecryptfs@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-bluetooth@vger.kernel.org,
	linux-wpan@vger.kernel.org,
	linux-sctp@vger.kernel.org,
	linux-nfs@vger.kernel.org,
	tipc-discussion@lists.sourceforge.net,
	cocci@systeme.lip6.fr,
	linux-security-module@vger.kernel.org,
	linux-integrity@vger.kernel.org,
	Waiman Long <longman@redhat.com>
Subject: [PATCH v2 2/2] crypto: Remove unnecessary memzero_explicit()
Date: Mon, 13 Apr 2020 18:28:46 -0400
Message-Id: <20200413222846.24240-1-longman@redhat.com>
In-Reply-To: <20200413211550.8307-1-longman@redhat.com>
References: <20200413211550.8307-1-longman@redhat.com>
X-Scanned-By: MIMEDefang 2.84 on 10.5.11.22
X-Original-Sender: longman@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=a2qwqlIc;
       spf=pass (google.com: domain of longman@redhat.com designates
 207.211.31.81 as permitted sender) smtp.mailfrom=longman@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Content-Type: text/plain; charset="UTF-8"
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

Since kfree_sensitive() will do an implicit memzero_explicit(), there
is no need to call memzero_explicit() before it. Eliminate those
memzero_explicit() and simplify the call sites. For better correctness,
the setting of keylen is also moved down after the key pointer check.

Signed-off-by: Waiman Long <longman@redhat.com>
---
 .../allwinner/sun8i-ce/sun8i-ce-cipher.c      | 19 +++++-------------
 .../allwinner/sun8i-ss/sun8i-ss-cipher.c      | 20 +++++--------------
 drivers/crypto/amlogic/amlogic-gxl-cipher.c   | 12 +++--------
 drivers/crypto/inside-secure/safexcel_hash.c  |  3 +--
 4 files changed, 14 insertions(+), 40 deletions(-)

diff --git a/drivers/crypto/allwinner/sun8i-ce/sun8i-ce-cipher.c b/drivers/crypto/allwinner/sun8i-ce/sun8i-ce-cipher.c
index aa4e8fdc2b32..8358fac98719 100644
--- a/drivers/crypto/allwinner/sun8i-ce/sun8i-ce-cipher.c
+++ b/drivers/crypto/allwinner/sun8i-ce/sun8i-ce-cipher.c
@@ -366,10 +366,7 @@ void sun8i_ce_cipher_exit(struct crypto_tfm *tfm)
 {
 	struct sun8i_cipher_tfm_ctx *op = crypto_tfm_ctx(tfm);
 
-	if (op->key) {
-		memzero_explicit(op->key, op->keylen);
-		kfree(op->key);
-	}
+	kfree_sensitive(op->key);
 	crypto_free_sync_skcipher(op->fallback_tfm);
 	pm_runtime_put_sync_suspend(op->ce->dev);
 }
@@ -391,14 +388,11 @@ int sun8i_ce_aes_setkey(struct crypto_skcipher *tfm, const u8 *key,
 		dev_dbg(ce->dev, "ERROR: Invalid keylen %u\n", keylen);
 		return -EINVAL;
 	}
-	if (op->key) {
-		memzero_explicit(op->key, op->keylen);
-		kfree(op->key);
-	}
-	op->keylen = keylen;
+	kfree_sensitive(op->key);
 	op->key = kmemdup(key, keylen, GFP_KERNEL | GFP_DMA);
 	if (!op->key)
 		return -ENOMEM;
+	op->keylen = keylen;
 
 	crypto_sync_skcipher_clear_flags(op->fallback_tfm, CRYPTO_TFM_REQ_MASK);
 	crypto_sync_skcipher_set_flags(op->fallback_tfm, tfm->base.crt_flags & CRYPTO_TFM_REQ_MASK);
@@ -416,14 +410,11 @@ int sun8i_ce_des3_setkey(struct crypto_skcipher *tfm, const u8 *key,
 	if (err)
 		return err;
 
-	if (op->key) {
-		memzero_explicit(op->key, op->keylen);
-		kfree(op->key);
-	}
-	op->keylen = keylen;
+	kfree_sensitive(op->key);
 	op->key = kmemdup(key, keylen, GFP_KERNEL | GFP_DMA);
 	if (!op->key)
 		return -ENOMEM;
+	op->keylen = keylen;
 
 	crypto_sync_skcipher_clear_flags(op->fallback_tfm, CRYPTO_TFM_REQ_MASK);
 	crypto_sync_skcipher_set_flags(op->fallback_tfm, tfm->base.crt_flags & CRYPTO_TFM_REQ_MASK);
diff --git a/drivers/crypto/allwinner/sun8i-ss/sun8i-ss-cipher.c b/drivers/crypto/allwinner/sun8i-ss/sun8i-ss-cipher.c
index 5246ef4f5430..0495fbc27fcc 100644
--- a/drivers/crypto/allwinner/sun8i-ss/sun8i-ss-cipher.c
+++ b/drivers/crypto/allwinner/sun8i-ss/sun8i-ss-cipher.c
@@ -249,7 +249,6 @@ static int sun8i_ss_cipher(struct skcipher_request *areq)
 			offset = areq->cryptlen - ivsize;
 			if (rctx->op_dir & SS_DECRYPTION) {
 				memcpy(areq->iv, backup_iv, ivsize);
-				memzero_explicit(backup_iv, ivsize);
 				kfree_sensitive(backup_iv);
 			} else {
 				scatterwalk_map_and_copy(areq->iv, areq->dst, offset,
@@ -367,10 +366,7 @@ void sun8i_ss_cipher_exit(struct crypto_tfm *tfm)
 {
 	struct sun8i_cipher_tfm_ctx *op = crypto_tfm_ctx(tfm);
 
-	if (op->key) {
-		memzero_explicit(op->key, op->keylen);
-		kfree(op->key);
-	}
+	kfree_sensitive(op->key);
 	crypto_free_sync_skcipher(op->fallback_tfm);
 	pm_runtime_put_sync(op->ss->dev);
 }
@@ -392,14 +388,11 @@ int sun8i_ss_aes_setkey(struct crypto_skcipher *tfm, const u8 *key,
 		dev_dbg(ss->dev, "ERROR: Invalid keylen %u\n", keylen);
 		return -EINVAL;
 	}
-	if (op->key) {
-		memzero_explicit(op->key, op->keylen);
-		kfree(op->key);
-	}
-	op->keylen = keylen;
+	kfree_sensitive(op->key);
 	op->key = kmemdup(key, keylen, GFP_KERNEL | GFP_DMA);
 	if (!op->key)
 		return -ENOMEM;
+	op->keylen = keylen;
 
 	crypto_sync_skcipher_clear_flags(op->fallback_tfm, CRYPTO_TFM_REQ_MASK);
 	crypto_sync_skcipher_set_flags(op->fallback_tfm, tfm->base.crt_flags & CRYPTO_TFM_REQ_MASK);
@@ -418,14 +411,11 @@ int sun8i_ss_des3_setkey(struct crypto_skcipher *tfm, const u8 *key,
 		return -EINVAL;
 	}
 
-	if (op->key) {
-		memzero_explicit(op->key, op->keylen);
-		kfree(op->key);
-	}
-	op->keylen = keylen;
+	kfree_sensitive(op->key);
 	op->key = kmemdup(key, keylen, GFP_KERNEL | GFP_DMA);
 	if (!op->key)
 		return -ENOMEM;
+	op->keylen = keylen;
 
 	crypto_sync_skcipher_clear_flags(op->fallback_tfm, CRYPTO_TFM_REQ_MASK);
 	crypto_sync_skcipher_set_flags(op->fallback_tfm, tfm->base.crt_flags & CRYPTO_TFM_REQ_MASK);
diff --git a/drivers/crypto/amlogic/amlogic-gxl-cipher.c b/drivers/crypto/amlogic/amlogic-gxl-cipher.c
index fd1269900d67..6aa9ce7bbbd4 100644
--- a/drivers/crypto/amlogic/amlogic-gxl-cipher.c
+++ b/drivers/crypto/amlogic/amlogic-gxl-cipher.c
@@ -341,10 +341,7 @@ void meson_cipher_exit(struct crypto_tfm *tfm)
 {
 	struct meson_cipher_tfm_ctx *op = crypto_tfm_ctx(tfm);
 
-	if (op->key) {
-		memzero_explicit(op->key, op->keylen);
-		kfree(op->key);
-	}
+	kfree_sensitive(op->key);
 	crypto_free_sync_skcipher(op->fallback_tfm);
 }
 
@@ -368,14 +365,11 @@ int meson_aes_setkey(struct crypto_skcipher *tfm, const u8 *key,
 		dev_dbg(mc->dev, "ERROR: Invalid keylen %u\n", keylen);
 		return -EINVAL;
 	}
-	if (op->key) {
-		memzero_explicit(op->key, op->keylen);
-		kfree(op->key);
-	}
-	op->keylen = keylen;
+	kfree_sensitive(op->key);
 	op->key = kmemdup(key, keylen, GFP_KERNEL | GFP_DMA);
 	if (!op->key)
 		return -ENOMEM;
+	op->keylen = keylen;
 
 	return crypto_sync_skcipher_setkey(op->fallback_tfm, key, keylen);
 }
diff --git a/drivers/crypto/inside-secure/safexcel_hash.c b/drivers/crypto/inside-secure/safexcel_hash.c
index 43962bc709c6..4a2d162914de 100644
--- a/drivers/crypto/inside-secure/safexcel_hash.c
+++ b/drivers/crypto/inside-secure/safexcel_hash.c
@@ -1081,8 +1081,7 @@ static int safexcel_hmac_init_pad(struct ahash_request *areq,
 		}
 
 		/* Avoid leaking */
-		memzero_explicit(keydup, keylen);
-		kfree(keydup);
+		kfree_sensitive(keydup);
 
 		if (ret)
 			return ret;
-- 
2.18.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200413222846.24240-1-longman%40redhat.com.
