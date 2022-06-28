Return-Path: <kasan-dev+bncBDN3FGENWMIRB6M35OKQMGQEYXXKGXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93e.google.com (mail-ua1-x93e.google.com [IPv6:2607:f8b0:4864:20::93e])
	by mail.lfdr.de (Postfix) with ESMTPS id C286255BFD8
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 11:46:34 +0200 (CEST)
Received: by mail-ua1-x93e.google.com with SMTP id g5-20020ab060c5000000b00378f363f03bsf4996817uam.15
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 02:46:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656409593; cv=pass;
        d=google.com; s=arc-20160816;
        b=mGXZSWCo7wbOHUttgscaPKcSZmCUUR7OwlHwj/MqJXEe4KQLqya/tWWB/zChFBgKVr
         xp+gOpJSUjnA52SNQ1qx8OL/xcT+ij41x6ph25VjIl37hALsZSIisIyzWr8/ue3CnLts
         aiewe3nci/1BaFRkxEtVSBi39TShQ1OpI9etD4T8TPl7LnAIgQZ42F2W0zTPU0l9hDlu
         KnKj8IX3vQ22ca6WTcR5HMnbNt+DXUQ3QXDaKCP8L/vFiHcnErA2n0ZNoCFTOZMSZpfC
         qquixIeTWAYYfHvTcG6bTPGtQnVzTTUzcwRwBjl02rtmb9DeBYC1qVPK6QkDX1HxogFG
         DaSg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=768Dsr4KyAnQ6R6w/dFeRWZc0UGw5kGz3nGHIpeiSGI=;
        b=A4cztSqj4pl8v5xwtN0v12kP/El+mg2bO4ielqZpJRq477HdKqExnAJSiRhRr03RNa
         c63Ue2edeEKP1hZmq6CQIlwBogBA2NuvOCBzXCCUVYonDbWsDCa+c/RTBp8EjI3/f35h
         oXJ6zjtIPJhp3+33esychDFoLDh1/WRy6nzGVYVWNv7u71n4Bx14Ln2P9YAdm9HAdVrE
         YczM1dzcMTEkZ3nT+5Eed2wWlxPEmXdYXVjC2dITcyl3kVo7q3VAJVLUOjPG/afrOM2l
         t7ZCh024Ot801pivGTbutIAWuJkJ0K58ZA79wTl683wbNovZ0lzDNeTDUzEK54bs1Emb
         G4wg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=QKNOLdAg;
       spf=pass (google.com: domain of mchehab@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=mchehab@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=768Dsr4KyAnQ6R6w/dFeRWZc0UGw5kGz3nGHIpeiSGI=;
        b=tPiMw1Pv75QQ29Ns3BSHYo2p2yclxMgurn/Zf+PoVUO8rrE539sdOsp2CQ0PMoPO4q
         WE1xPFDQcT+PH+tmGTxnaMO3+9pbKzlNqVebG5pu95qdOW5pQrHWT7JyYFnCCxps7JPh
         hpFimGN0wAllvYpBQNxdgwJN4JGWuDUVAI1omTHJI66NvXLJKUA/s8uJXmiQAjgE0680
         chgAla7UXn6ggjn1nDzaa6nq/cNnEDkEY1mTVhvyMaF1pEzcGy+5kfkQhdm6K6PE0Y4I
         sDH1X/+6evSoCMgF2qTSor/KXPdjDsgMh6eMzB0ebZKBRAhxyzu7l0hEuCdbFMXkYAiZ
         qUzA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=768Dsr4KyAnQ6R6w/dFeRWZc0UGw5kGz3nGHIpeiSGI=;
        b=Kb1QdAqYHbM4oxMqMZdD9UJL+IIWofpRAAgfRzSzB/KEHr7P3IBUEciLDIlXT83p89
         mAq/PrJ+n7Wh0yDWZgFBthdaIcTVR7KbPGWm3z68w/wMl5PIk7xxZGLPzuWndDk2fMXD
         sMol3YM2M7l7z4VIquICosGxD1MJ9l54Gf0o3CmeTfPKj/Wc2Fnr72/LI5kg2aZUejFM
         27urquF2F2ZjjVsMXgPQzayc595a4fFNThiE55OJUVPRRg0nJAy03DP9vV0ytfNV8MRJ
         cr2AgCehqFmdWpkJPkQdcgUDQAZRsZLakjZn1DKtqYB9uyk7Zt/s/f/scqkzYInfaS1K
         eYxg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora9q2k+nk/oomo0LR1cdcXv2KCRvXrv5LnDKTykUMdJABxRE5B3V
	ajXcmKwQ5S3GL/xx7w4CdFQ=
X-Google-Smtp-Source: AGRyM1vXy9+pup/m7CzOe7EOMS8C8VmFCioKa/ZOqclUJekW/QfevfJsFZ5A/BCMeqIhMjhvS0Y7aQ==
X-Received: by 2002:a67:ce81:0:b0:354:4b7f:e653 with SMTP id c1-20020a67ce81000000b003544b7fe653mr806132vse.30.1656409593441;
        Tue, 28 Jun 2022 02:46:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:4343:0:b0:36c:b8d6:3ff0 with SMTP id q64-20020a1f4343000000b0036cb8d63ff0ls1104677vka.8.gmail;
 Tue, 28 Jun 2022 02:46:32 -0700 (PDT)
X-Received: by 2002:a1f:9e53:0:b0:370:3d3c:4ca7 with SMTP id h80-20020a1f9e53000000b003703d3c4ca7mr937035vke.40.1656409592816;
        Tue, 28 Jun 2022 02:46:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656409592; cv=none;
        d=google.com; s=arc-20160816;
        b=yFfJARr0gDeZZy3Ps9txuROenGTtMmKkDIOAwLVQoX2ZA2DL7teKNjGOrnETrXVxm6
         iYMLHmEE/zc93zVTCLTcFwL1KVUwJzpBVoTrNZnJPnn8thE07D95Sj4OyrtPFk7/ocek
         GJH9K9ipuelA3DZlKtMk+J5ccNsozFOPUSv7Tam4gy6p4SX5/YjyKO6CbmMYDPcyPSI/
         V0uGYYi8jG0CEZw44yESah8n9D65EOX+gXKidkzJ4Htw3x3ftq+rkl/N6dfeBSgVQlDw
         z+AQp7g9p7l8+1TF5/p7RuZ9j36yf2Q6hGy2ZRC9oYJ+4Vu+ZpdEjZA7xAkGMVoMNx7D
         NlZg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=q7+xShBlSge2SYJ0a+VxfghsDlKRo2gfVGiFs4bcrkk=;
        b=ZCNcBWVJB0PRZq6lppa/TW2xjp9/SSeQZAaUg6DV4MbvFiTAiXMtsmsA5WqA37Vn8m
         6ytGh1bEKIZnFDDp81sqGu6945s5IsqSzr6+uLet+0HIwYm8VOYt+kZctntvtOdnQlmn
         +PouRJFAsPvS6dr4cWuBQsvRfyda6ruvSW6PVBXT8UX2UDkGowO4HhMX7GJVOV6vNjkN
         JiPas7Ei/I4agdX63UvcJYnmafJZJWjCk9Ue71/9/90m5VsXKw/zs2db7BHpLaf1B27I
         NpgYUGlfySzh9OMlxv16dp6w6vT3/nxv6OnTYiJEkMHNKdIFiAqXwHoZxpXYREwROYAw
         H2NQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=QKNOLdAg;
       spf=pass (google.com: domain of mchehab@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=mchehab@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id p65-20020a1fa644000000b003700a12ecbcsi247828vke.5.2022.06.28.02.46.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 28 Jun 2022 02:46:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of mchehab@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 4F26661827;
	Tue, 28 Jun 2022 09:46:32 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 580D6C36AEB;
	Tue, 28 Jun 2022 09:46:30 +0000 (UTC)
Received: from mchehab by mail.kernel.org with local (Exim 4.95)
	(envelope-from <mchehab@kernel.org>)
	id 1o67nf-005HFX-Tp;
	Tue, 28 Jun 2022 10:46:27 +0100
From: Mauro Carvalho Chehab <mchehab@kernel.org>
To: Linux Doc Mailing List <linux-doc@vger.kernel.org>
Cc: Mauro Carvalho Chehab <mchehab@kernel.org>,
	=?UTF-8?q?Christian=20K=C3=B6nig?= <christian.koenig@amd.com>,
	"Jonathan Corbet" <corbet@lwn.net>,
	"Mauro Carvalho Chehab" <mchehab+huawei@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Marco Elver <elver@google.com>,
	Sumit Semwal <sumit.semwal@linaro.org>,
	dri-devel@lists.freedesktop.org,
	kasan-dev@googlegroups.com,
	linaro-mm-sig@lists.linaro.org,
	linux-kernel@vger.kernel.org,
	linux-media@vger.kernel.org
Subject: [PATCH 14/22] kfence: fix a kernel-doc parameter
Date: Tue, 28 Jun 2022 10:46:18 +0100
Message-Id: <687a2e724020d135bc7dfef0ec9010a00ecc0a3a.1656409369.git.mchehab@kernel.org>
X-Mailer: git-send-email 2.36.1
In-Reply-To: <cover.1656409369.git.mchehab@kernel.org>
References: <cover.1656409369.git.mchehab@kernel.org>
MIME-Version: 1.0
X-Original-Sender: mchehab@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=QKNOLdAg;       spf=pass
 (google.com: domain of mchehab@kernel.org designates 139.178.84.217 as
 permitted sender) smtp.mailfrom=mchehab@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

The kernel-doc markup is missing the slab pointer description:

	include/linux/kfence.h:221: warning: Function parameter or member 'slab' not described in '__kfence_obj_info'

Document it.

Signed-off-by: Mauro Carvalho Chehab <mchehab@kernel.org>
---

To avoid mailbombing on a large number of people, only mailing lists were C/C on the cover.
See [PATCH 00/22] at: https://lore.kernel.org/all/cover.1656409369.git.mchehab@kernel.org/

 include/linux/kfence.h | 1 +
 1 file changed, 1 insertion(+)

diff --git a/include/linux/kfence.h b/include/linux/kfence.h
index 726857a4b680..9c242f4e9fab 100644
--- a/include/linux/kfence.h
+++ b/include/linux/kfence.h
@@ -210,6 +210,7 @@ struct kmem_obj_info;
  * __kfence_obj_info() - fill kmem_obj_info struct
  * @kpp: kmem_obj_info to be filled
  * @object: the object
+ * @slab: pointer to slab
  *
  * Return:
  * * false - not a KFENCE object
-- 
2.36.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/687a2e724020d135bc7dfef0ec9010a00ecc0a3a.1656409369.git.mchehab%40kernel.org.
