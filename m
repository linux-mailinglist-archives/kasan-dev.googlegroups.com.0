Return-Path: <kasan-dev+bncBCCMH5WKTMGRBSVJUSNQMGQELLOD2II@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 9D9AA61F5C1
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Nov 2022 15:23:07 +0100 (CET)
Received: by mail-lf1-x139.google.com with SMTP id a26-20020ac25e7a000000b004b21ed7d4e4sf1935297lfr.15
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Nov 2022 06:23:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1667830987; cv=pass;
        d=google.com; s=arc-20160816;
        b=F/t2HdbHvGSaBbitWCeIm6UDJ2GVIMyRfalcbwfBcN7U7iRVH5cD8jQEJeT3Vu3LRN
         elTW6jcw2/mdJO6XvrHDDhUZOWwmoE28zHia23nqZZxaUlJnJBAsPdTB05DW5ZB61mMm
         FlLi8FsdTenn1z9DpEneZYzI7mYpCb/xxp1/wpogouZ9JxvZkR1vQBieEssC2lfVGq17
         +fUE0ateL2vpmKmw8f4GqIs+72p27QdLPS+g7i6YIgURVXvXAwjF7wu4AHYqrIgJmr+k
         EmdbBtYnLOr1XwKMDAAQWIvJgA8ROVsmJ/ZcyZmm+9PpJT+1ex/PFqwZ2ezIx97rUrft
         w8jw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=1oyJt+LcxLbo5WuKlFlmd0Cwp0xUqbvlwDIg4wGix3c=;
        b=UoLf175+LvzW9lURUTHTWHZXDADzZPUFyDwU6kbG251aBTuj/tDO8O9jqNWAtCBcmM
         ZJEMhOLMh5d1ZgZAIkRALfdCCUBEX/T0y7Nc6DOMFyaOclTLOnUc8CsbeiuOJMTZif3S
         GNvNQ0o263FZTwQ6OuzJhBUM6WtnN0Hk2vdY+RVgEzwYW3Ntd9+Dzi5TzNs6F2svmZLf
         5V01RJcLTNhqXquD6KuziBCJEsM8S8DqaVrLc9sNF0F1Oau2pKhSfuGOCsAbFtQt00Mb
         bOlpZ5Rtp8aRoCrhkDh8W2cX427m2wQkgLMaGAmCcPHeVqs9+v1eE1W+69VOtewfSimn
         sfyQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=VgwTO2WL;
       spf=pass (google.com: domain of 3ybrpywykcbcdifabodlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--glider.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3yBRpYwYKCbcdifabodlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=1oyJt+LcxLbo5WuKlFlmd0Cwp0xUqbvlwDIg4wGix3c=;
        b=sn4IwJufFabrMR7yYxscX/rmz4QC92VyHkofMHwSrYrtUJ5bDd4vNsR2vjLfhS7Cc6
         8Gkg5Pz166hhlnGyUqH0eLv341vTrt5/2qxaE2Bkf4Elfk/cDxCFbK3UMcYdmjEPjNhl
         3TUy7JLRZsNRjxJVPSyiaBg8OEdNo9Xcl8ylsuiZY1zzLkfK6aEIKtqVVMNzjA225+PB
         +wiXgFO8bCxrB+mC930qXeL/S6rkywL0WZuYXidNlkhgvv9I1uN6RSrkjKS5TTG7v+Oo
         C7ojMzahVkIhb01Vv9DBuxy/cMzRMeXSGxBp2Tbukj90QpkMNMTFfiGhGoIjgpUyTD7R
         iHNg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=1oyJt+LcxLbo5WuKlFlmd0Cwp0xUqbvlwDIg4wGix3c=;
        b=AphT8iZFrnDiA6VkgZN+bxdBvEFt7F0eBiMpb8Xpkehwj7ECzOBvpGVmRGYdamTIms
         j/vbPAvjPzTqSpKqUVZy8FAt5ndUVKSkJOFp8/YewCpr0jBzXNUHmXXnkrVYZChaIxb1
         SOjyn6hqpqAU1fbsNjrabC9RgHctO3X++zGjCNzeC0IOt4+7dSXoTYDNnG6fIyeXo9nu
         AqpDg9mY5gkXy8RC0OBeY8MYOaGj4CSg3ANMsMfPH1HQObCT9Qh99HR/6C5ZN9mCA0Gl
         fR83OuDbdv4K5/GGwUCddBuZvHWkpWvNme2z/Km1pInBDltl+hI+cUP6uYlDuUjbyb/n
         jPyw==
X-Gm-Message-State: ACrzQf2oWPg41/+LIvAktyM9X+FkVtfz6LumrFhGOIvVSOwM2Yx7RrJZ
	t6xeslNmswD0b/EQ7/xLAzU=
X-Google-Smtp-Source: AMsMyM7tuJb4X8CpbQgl+uhN7IYbUqPHPxZhklVJ0ZnSRM5GO10/7j4LPwuVZkr0zHooYef0U+zoWA==
X-Received: by 2002:a05:6512:22c3:b0:4a2:1698:58db with SMTP id g3-20020a05651222c300b004a2169858dbmr19751470lfu.554.1667830986535;
        Mon, 07 Nov 2022 06:23:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:12c1:b0:277:1d5b:1cc7 with SMTP id
 1-20020a05651c12c100b002771d5b1cc7ls2378731lje.3.-pod-prod-gmail; Mon, 07 Nov
 2022 06:23:05 -0800 (PST)
X-Received: by 2002:a05:651c:88b:b0:26e:261:5052 with SMTP id d11-20020a05651c088b00b0026e02615052mr16756482ljq.182.1667830985370;
        Mon, 07 Nov 2022 06:23:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1667830985; cv=none;
        d=google.com; s=arc-20160816;
        b=SVwSDUlWzO0034ujOcIe/u4Gxjnl8XIPp1JEaa4g03ToFwH7XHiXj6jIsyuRGs9YBD
         DoOI4Acg6PpAB5V6XneXwF6d13eLy7ljlGLB/JLynDeFqZku1rUfwR+AeHkEAhT7izB9
         bSV7j82qpxSnrmLL7HVR/AqUyc3oPwWuWeOyqwNp2jbF0p89wvUZ2pdcz1f5LQhCz6JQ
         4oOaPQKuumDjPomkgHCCeYpTLzg4oJ4krSsAb/OzzGJ7n4n92RbmU2pXrXqwtiqXtllW
         erMTIkJI1QIR/dgga/z5qDRTvrhtrtfBQbRWnA+L3qPPDNpc28rMzp3d/I6T7vOGXEpV
         mPqw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=8RGh8EDyO4osN/zuXgwdm42OK5Fa8r6gvjPxQC6gE/Y=;
        b=fCSLzdYUYsuH4s3xmRiVpSUh9xVJQi3+kl5/1GzxCWirPa4p24VuNV1VL7GftrvrAP
         7WOfvJAYXrjmO0suEGipR1FfUnUXRuIW9LFhd0B1QSfGdMhMCzwFz2jwiVX5faz08S0J
         92WncHUimB9ZDph7VcARhG5GMA2EHZivKcD0+kqT6QxdPsuB2vqp7U/wvkkpNcUshejW
         quR6ePNpWgZPkNDVBmp0575P9FuNlbQE1Omt9Eahi+KC6q4UmWFS/MNntRYZ0kcKZm7L
         AinLCSVR10n+h2BtcPFX9ektnLTpV/bOXkknkLASF1Evwrze+uIZeZ5LtXZaJ2ugJdFZ
         cpLA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=VgwTO2WL;
       spf=pass (google.com: domain of 3ybrpywykcbcdifabodlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--glider.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3yBRpYwYKCbcdifabodlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id p18-20020a2eb992000000b002773925701bsi312705ljp.1.2022.11.07.06.23.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Nov 2022 06:23:05 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ybrpywykcbcdifabodlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--glider.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id j20-20020adfb314000000b002366d9f67aaso2814731wrd.3
        for <kasan-dev@googlegroups.com>; Mon, 07 Nov 2022 06:23:05 -0800 (PST)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:4f3e:16fb:f499:bb9d])
 (user=glider job=sendgmr) by 2002:adf:e78d:0:b0:236:debd:f681 with SMTP id
 n13-20020adfe78d000000b00236debdf681mr23955346wrm.17.1667830984850; Mon, 07
 Nov 2022 06:23:04 -0800 (PST)
Date: Mon,  7 Nov 2022 15:22:55 +0100
Mime-Version: 1.0
X-Mailer: git-send-email 2.38.1.431.g37b22c650d-goog
Message-ID: <20221107142255.4038811-1-glider@google.com>
Subject: [PATCH] docs: kmsan: fix formatting of "Example report"
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: linux-kernel@vger.kernel.org, linux-doc@vger.kernel.org, 
	akpm@linux-foundation.org, corbet@lwn.net, kasan-dev@googlegroups.com, 
	Bagas Sanjaya <bagasdotme@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=VgwTO2WL;       spf=pass
 (google.com: domain of 3ybrpywykcbcdifabodlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3yBRpYwYKCbcdifabodlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

Add a blank line to make the sentence before the list render as a
separate paragraph, not a definition.

Fixes: 93858ae70cf4 ("kmsan: add ReST documentation")
Suggested-by: Bagas Sanjaya <bagasdotme@gmail.com>
Signed-off-by: Alexander Potapenko <glider@google.com>
---
 Documentation/dev-tools/kmsan.rst | 1 +
 1 file changed, 1 insertion(+)

diff --git a/Documentation/dev-tools/kmsan.rst b/Documentation/dev-tools/kmsan.rst
index 2a53a801198cb..55fa82212eb25 100644
--- a/Documentation/dev-tools/kmsan.rst
+++ b/Documentation/dev-tools/kmsan.rst
@@ -67,6 +67,7 @@ uninitialized in the local variable, as well as the stack where the value was
 copied to another memory location before use.
 
 A use of uninitialized value ``v`` is reported by KMSAN in the following cases:
+
  - in a condition, e.g. ``if (v) { ... }``;
  - in an indexing or pointer dereferencing, e.g. ``array[v]`` or ``*v``;
  - when it is copied to userspace or hardware, e.g. ``copy_to_user(..., &v, ...)``;
-- 
2.38.1.431.g37b22c650d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221107142255.4038811-1-glider%40google.com.
