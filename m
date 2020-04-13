Return-Path: <kasan-dev+bncBCPILY4NUAFBBRVN2P2AKGQEM5QYROQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id 86AAA1A6DDC
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Apr 2020 23:16:55 +0200 (CEST)
Received: by mail-qv1-xf38.google.com with SMTP id x9sf9253485qvj.8
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Apr 2020 14:16:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1586812614; cv=pass;
        d=google.com; s=arc-20160816;
        b=xUQ5VDnn+tlM9VBmegvRqBS0tp85QKfASHLZX/dG8kvvwOv8TyeyDxFm6BHTXlWcgk
         TXomLm6NZUHDKmGPO0A6mwY83eKa5WNe5FjfG3NCp3kagzpCfo2gvaARnqMKEy/5VeDk
         4Vc3JM5BDi5VK0KnxhRlvBH4Kxhus9+8A42Sp2f0c5l7z8aiV3dkpEcJk/1D4zTR13SS
         7o9ENAEPzHLrITScpzebzE24mv4BrEKgarX7Gx4LZfqPTsxEnK2hfYhn4Fq//130hHFU
         RQauNHHAXr7yDQlDdTAhGzmBt9bvK8cpeP5sd2sQr2ZXy66xrwjHnK7dQJQffhcL36WO
         dH8A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=tjobM8PNa8Z00VfvbfImayWyk+xfXbFVsHEG9UxfzEs=;
        b=YIRg+9DigRPoE/c3Qd66Of6UWOxS/EPSaO0+bLaoVI8/vGuMX1MH6WDkmCt7sWlfVD
         qxH+iR/TGbH4mzi2T4NF8L+e7MIMTZ+iM+A+dAQok+0pNjogba7hyzFL5GgcXQizZf6b
         Bgw/Pwvnsli3u1cZ3ij9TXfSJuz0ctAtCFHl1/Sbq+fZW2yp5wQ1DhNFUFjTPHqohgga
         HZFq+UU58Wfj9+4QNaC68DnAIZqQMjMosT6jEPtaaOcghOQZeMPJhwQDpT+amCNaCr08
         KMzk7h4jGpfYtQhNmvmH1DufnSnunxYFf+K11pZssarJspHHhYmwiAtoBsarDXd/rJWy
         qGmw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=E+gP7Dfd;
       spf=pass (google.com: domain of longman@redhat.com designates 205.139.110.61 as permitted sender) smtp.mailfrom=longman@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tjobM8PNa8Z00VfvbfImayWyk+xfXbFVsHEG9UxfzEs=;
        b=b0/hSHvZN3wI8eHyKCN+pjTV6UjgbHfJYCBnU6lTnu8JfC5Nc2aY0B6ctWe+7TqakM
         IDDHIwAdQD7YTJcMEsR9enwDnSMgQoIyTLZC73yv066i98a/SVlHsuWqXdUedsK/dwwd
         uY1T8EE0P1YJI2EE2m8IxvHyrWR/3SfCLVuE/Y8r/xGOfq+Zs0jXaeIHOb7g2MeDKlQC
         yrOQhdv+xRs/Og0s/i3h6YCdNzzWy+Y1HoZwAI54omjXaL8v4CZG+UZ+NhZRQX5WNO2M
         oWijEjN2698a2trbKvD4ECgNU6c2c7ggXvpVGDe8JVMcIsv3E+8ACu/prISzMPmOkB52
         Ti6A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tjobM8PNa8Z00VfvbfImayWyk+xfXbFVsHEG9UxfzEs=;
        b=mH7ylRy/mIQYD1jwbSQth2QnEiETeOu1XIM67m+ZQ+X/ONZKtbRIKKCBir6JtyedUM
         yPB5eYzZt3bydt3l3t9uXG3Fxo9zsDHt6mD9SnHC4FXCezatXPgxxlwb5pyT9BPWg3yR
         kLJv47AuqjiTE8yg5de5Oqet+HUCvjtmBkfEeDDGAKDsFY3kbccCblSXUEmfLN57geYM
         yBnb6YF8ik2X+zEuu5bp8Jfnnea1m4vYKwmTDFC+uMjrvD6LcKK5WOwzWh/tTEhCzVyo
         fkIfgRNEg3J2lUaKje/NMmLcDE4xAD45GK3nUBjvKY7ZLgghBIFu+edXHFUMqVHzV5Is
         EFVw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuZ/4SXnaoFvRy5A/E8vWIj+X4WrNFqP21pD6SQitERDuPhRdSf1
	bELH/BxCSLmthIPF5e6E0hE=
X-Google-Smtp-Source: APiQypILtw0B9uHYHM+wRUtTQThv6dwOaC1tCRU8jB8GBzvt49SS/DY483+VAL6ck+k6o4a/uIk8gA==
X-Received: by 2002:a0c:de12:: with SMTP id t18mr18244540qvk.202.1586812614573;
        Mon, 13 Apr 2020 14:16:54 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:9e17:: with SMTP id h23ls839861qke.7.gmail; Mon, 13 Apr
 2020 14:16:54 -0700 (PDT)
X-Received: by 2002:ae9:f44a:: with SMTP id z10mr18758860qkl.353.1586812614146;
        Mon, 13 Apr 2020 14:16:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1586812614; cv=none;
        d=google.com; s=arc-20160816;
        b=nSU9gBhUFQN9UdDKaJYccSLHtTEAS1aSVbOYIqqvGfcUU6FimQEExEiNFJ4DqhYvfk
         dB5YJJZt8vFD1ylSFxAV6WcRikx3bjEPrAol4vsMSFT+Do16zN5ahC9uiyZAUSD6EisP
         HjVI/864HPgBLocaloYtqMxA/SkBTQDBxxmv9L5dustFtyvrfIN0P3mKqn8Bc3B6Q9+h
         8F11158UFfv1UNi1te32rDKp1EHr0WdxFkbTVEKRYcD3Jg5JAy129d/LIT8MSqzGdng5
         nLS6zM7A/1T9MTAq8DeWiHc1JOrLg7B/P4nc/cCJ7U2otNPQtKvhhrnN9YPYijx57xpl
         LPFg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=nDsD8ARELWs0d4asbSq1NjjS9iTGbr+u27Se40H771Q=;
        b=uih5iIr0LcU3TWbIekKU+2/q5jYkGua+vx+Ils27308TU/V4OCUReQaALWYp+bJ6D7
         LZjCDRr6CyquPjw/eAbXjk8hExUDjaPULmxafNMWV4HUZrXrBMjBLThcsGYozkiEkiZ3
         sOXCn8r+F3MozmdaYkB5uWCo8bhmGmKqh5KFmeFJC9Ljq8DpFSmKp1/KoTprpNRCi4Db
         YrvX5q/TV7yffpF0rPLrkdiMlx5c+oyircEQ9fbGAsGcMPh1cOfen3zAmfl9tHvZHAwD
         bpWhm4A9lf+mfxFXELBg469vLXG/Uh1xANrKidgV/7N1Zr80QozQ1VvnagoKeC7PA+zG
         jPWA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=E+gP7Dfd;
       spf=pass (google.com: domain of longman@redhat.com designates 205.139.110.61 as permitted sender) smtp.mailfrom=longman@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-1.mimecast.com (us-smtp-2.mimecast.com. [205.139.110.61])
        by gmr-mx.google.com with ESMTPS id e11si835451qtw.1.2020.04.13.14.16.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 13 Apr 2020 14:16:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of longman@redhat.com designates 205.139.110.61 as permitted sender) client-ip=205.139.110.61;
Received: from mimecast-mx01.redhat.com (mimecast-mx01.redhat.com
 [209.132.183.4]) (Using TLS) by relay.mimecast.com with ESMTP id
 us-mta-346-rjIc-N9CM66LO5fX_MJoTg-1; Mon, 13 Apr 2020 17:16:49 -0400
X-MC-Unique: rjIc-N9CM66LO5fX_MJoTg-1
Received: from smtp.corp.redhat.com (int-mx01.intmail.prod.int.phx2.redhat.com [10.5.11.11])
	(using TLSv1.2 with cipher AECDH-AES256-SHA (256/256 bits))
	(No client certificate requested)
	by mimecast-mx01.redhat.com (Postfix) with ESMTPS id 64AE4107ACCA;
	Mon, 13 Apr 2020 21:16:44 +0000 (UTC)
Received: from llong.com (ovpn-115-28.rdu2.redhat.com [10.10.115.28])
	by smtp.corp.redhat.com (Postfix) with ESMTP id 1198311D2D3;
	Mon, 13 Apr 2020 21:16:39 +0000 (UTC)
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
Subject: [PATCH 2/2] crypto: Remove unnecessary memzero_explicit()
Date: Mon, 13 Apr 2020 17:15:50 -0400
Message-Id: <20200413211550.8307-3-longman@redhat.com>
In-Reply-To: <20200413211550.8307-1-longman@redhat.com>
References: <20200413211550.8307-1-longman@redhat.com>
X-Scanned-By: MIMEDefang 2.79 on 10.5.11.11
X-Original-Sender: longman@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=E+gP7Dfd;
       spf=pass (google.com: domain of longman@redhat.com designates
 205.139.110.61 as permitted sender) smtp.mailfrom=longman@redhat.com;
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
memzero_explicit() and simplify the call sites.

Signed-off-by: Waiman Long <longman@redhat.com>
---
 .../crypto/allwinner/sun8i-ce/sun8i-ce-cipher.c  | 15 +++------------
 .../crypto/allwinner/sun8i-ss/sun8i-ss-cipher.c  | 16 +++-------------
 drivers/crypto/amlogic/amlogic-gxl-cipher.c      | 10 ++--------
 drivers/crypto/inside-secure/safexcel_hash.c     |  3 +--
 4 files changed, 9 insertions(+), 35 deletions(-)

diff --git a/drivers/crypto/allwinner/sun8i-ce/sun8i-ce-cipher.c b/drivers/crypto/allwinner/sun8i-ce/sun8i-ce-cipher.c
index aa4e8fdc2b32..46c10c7ca6d0 100644
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
@@ -391,10 +388,7 @@ int sun8i_ce_aes_setkey(struct crypto_skcipher *tfm, const u8 *key,
 		dev_dbg(ce->dev, "ERROR: Invalid keylen %u\n", keylen);
 		return -EINVAL;
 	}
-	if (op->key) {
-		memzero_explicit(op->key, op->keylen);
-		kfree(op->key);
-	}
+	kfree_sensitive(op->key);
 	op->keylen = keylen;
 	op->key = kmemdup(key, keylen, GFP_KERNEL | GFP_DMA);
 	if (!op->key)
@@ -416,10 +410,7 @@ int sun8i_ce_des3_setkey(struct crypto_skcipher *tfm, const u8 *key,
 	if (err)
 		return err;
 
-	if (op->key) {
-		memzero_explicit(op->key, op->keylen);
-		kfree(op->key);
-	}
+	free_sensitive(op->key, op->keylen);
 	op->keylen = keylen;
 	op->key = kmemdup(key, keylen, GFP_KERNEL | GFP_DMA);
 	if (!op->key)
diff --git a/drivers/crypto/allwinner/sun8i-ss/sun8i-ss-cipher.c b/drivers/crypto/allwinner/sun8i-ss/sun8i-ss-cipher.c
index 5246ef4f5430..7e09a923cbaf 100644
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
@@ -392,10 +388,7 @@ int sun8i_ss_aes_setkey(struct crypto_skcipher *tfm, const u8 *key,
 		dev_dbg(ss->dev, "ERROR: Invalid keylen %u\n", keylen);
 		return -EINVAL;
 	}
-	if (op->key) {
-		memzero_explicit(op->key, op->keylen);
-		kfree(op->key);
-	}
+	kfree_sensitive(op->key);
 	op->keylen = keylen;
 	op->key = kmemdup(key, keylen, GFP_KERNEL | GFP_DMA);
 	if (!op->key)
@@ -418,10 +411,7 @@ int sun8i_ss_des3_setkey(struct crypto_skcipher *tfm, const u8 *key,
 		return -EINVAL;
 	}
 
-	if (op->key) {
-		memzero_explicit(op->key, op->keylen);
-		kfree(op->key);
-	}
+	kfree_sensitive(op->key);
 	op->keylen = keylen;
 	op->key = kmemdup(key, keylen, GFP_KERNEL | GFP_DMA);
 	if (!op->key)
diff --git a/drivers/crypto/amlogic/amlogic-gxl-cipher.c b/drivers/crypto/amlogic/amlogic-gxl-cipher.c
index fd1269900d67..f424397fbba4 100644
--- a/drivers/crypto/amlogic/amlogic-gxl-cipher.c
+++ b/drivers/crypto/amlogic/amlogic-gxl-cipher.c
@@ -341,10 +341,7 @@ void meson_cipher_exit(struct crypto_tfm *tfm)
 {
 	struct meson_cipher_tfm_ctx *op = crypto_tfm_ctx(tfm);
 
-	if (op->key) {
-		memzero_explicit(op->key, op->keylen);
-		kfree(op->key);
-	}
+	kfree_sensitive(op->key)
 	crypto_free_sync_skcipher(op->fallback_tfm);
 }
 
@@ -368,10 +365,7 @@ int meson_aes_setkey(struct crypto_skcipher *tfm, const u8 *key,
 		dev_dbg(mc->dev, "ERROR: Invalid keylen %u\n", keylen);
 		return -EINVAL;
 	}
-	if (op->key) {
-		memzero_explicit(op->key, op->keylen);
-		kfree(op->key);
-	}
+	kfree_sensitive(op->key);
 	op->keylen = keylen;
 	op->key = kmemdup(key, keylen, GFP_KERNEL | GFP_DMA);
 	if (!op->key)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200413211550.8307-3-longman%40redhat.com.
