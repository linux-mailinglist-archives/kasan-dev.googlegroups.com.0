Return-Path: <kasan-dev+bncBCQ2XPNX7EOBB6GQZH5QKGQEQBVCSLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id CDEA627B776
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Sep 2020 00:49:28 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id a17sf2464999lfl.4
        for <lists+kasan-dev@lfdr.de>; Mon, 28 Sep 2020 15:49:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601333368; cv=pass;
        d=google.com; s=arc-20160816;
        b=IGXQoR2M+2cUhKe/aFVof8H4GmrH8EvttWuzLshqkfFlv4Rg7M5evotc2NsyEL42DS
         caR78VtQe1Ky4Gt0XlXrCxOprTIWuPos2jsvyKWfuCD6L5Bqv6Ksch6ge89wtgeC1DtX
         6oYudOiELc/OvempcR8v/TD7vcLh+riquInIQseQ7hk3W0hPEsGEnj8tXgBPfXnFKy+Q
         00T/gMI0DXDGkUKcyJ5GlnQLUPBwW+/e5cKZoU3E/9DdXkbPubqwlR9txr62TlI1GGQS
         Gt3pxPHU9VrkBiQP0jonYmblgWOjXUMxeUBbATWrUnEe60VGhIKwW929YgTmFRim6W2J
         7o2w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:from:subject:mime-version:message-id:date:sender
         :dkim-signature;
        bh=juSf/ihJoeoTmqZiRYDReabvWnJeTPJpLy4Zrhs6UhA=;
        b=lIfCbgY+2XGbiziAWPdOw3RO50Hi1D8wm60E/Nmt/9ehuAKaG+vbceEW4fnEg2bgXE
         FIwTg54SXLaq7STM4rcqieTahZjBeSUn3CMcYXTqMXMP5u+Oj6F94uN03Z8sx/eRu5Fn
         KIUK/taxFUizvPebqqPbPqTtCWlVf0AeS4kdhlMyx3jyp3PXnExPZ+YVdYdRPd8lSXFW
         nkL7twvMojVxe+OX0tEnnO/aq48t5QV1UPyC79JikL3rth4GbB+l23Yu8azv948OSoQO
         kAJGK7mGl+KCGnbBtcHZJJCrnXKKRv/5LOAFV5wXqntdRe8Svk+0A34C1pXjTBMHNpoM
         pXpA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WCUoXB1S;
       spf=pass (google.com: domain of 3dmhyxwukcrm2t660z77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--jannh.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3dmhyXwUKCRM2t660z77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--jannh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:mime-version:subject:from:to:cc
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=juSf/ihJoeoTmqZiRYDReabvWnJeTPJpLy4Zrhs6UhA=;
        b=ZwXrRprFSk6niUuPxJ4EztAAkyZGCgKQ0lDgQ62qtVHL4ZTRTm6VxkCVd4Giiz8BBM
         kxkNoZ+Lv6lQVWiDmcqWR63kE0cMGP0fq1QX3N2Aa3ST1Nn9wbuvTKnGfx9XoZtsQV91
         qMcMxwxxBFy4hJ7Ira2m5mp/JPOKDnkESUukr7W0D/ghnLH+bXy4MGkUTJZSRgkOGUrM
         5A4L8t96VLSbpKy1uNYOTJXGwTICBQ1/ZC1lnOTbfG5cf3QAHBowA2bhqxuRQiXXRaXV
         5OE079+UTEAcZsDnnZ/1zqSZjt78teVsy2p3FzvTLh/nD1sfjP25y5miuDAjj1O/HP64
         TUlg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:message-id:mime-version:subject:from
         :to:cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=juSf/ihJoeoTmqZiRYDReabvWnJeTPJpLy4Zrhs6UhA=;
        b=Vc7oRC68SOAUzokFVlSe4CGWUPKTkveUvKQ8RLmCcbS9pRtE2PnIHPwt9By59UBUQp
         seaYZN2sc77Wbvj0gNIrxybdGyRCS9pNhnhEaCVnQlMBgMfGBY6IfogVswAGCjvh5agl
         CJ4MyEvaBOMRWufXJcaKWupljATHVWAIN9Z6j9CKEPhrurdTgZ+S2VB4eS6MqSCOzKmO
         dBcj7bTM7P1fN8mHCQitCQ28EYtNr4LKmKgn0x/eDyMxZaNIu3pn3wZ3N6D5CAJg2ek9
         u59d1maQCZ2wxKMaw4wKbRmHDKUXKwb9sZgfIlaUw8D4JG2280NJUnREeBH4EQwsxuTr
         i3LQ==
X-Gm-Message-State: AOAM533WX26R1wDrUrvZLVcI42fqTIQp9SdO3IV+h2tJW6NtRNtz/Gxf
	CF6SgBs/WEDy6dBo9wF8qN0=
X-Google-Smtp-Source: ABdhPJzk+dYw2W9Te2DMYpMfYaFyuM005PrNEwgLDWVolYEnwgG+8z8DTZWPTM/FsNbGzUdcPsefQw==
X-Received: by 2002:a05:6512:4cb:: with SMTP id w11mr136347lfq.33.1601333368407;
        Mon, 28 Sep 2020 15:49:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9151:: with SMTP id q17ls400854ljg.8.gmail; Mon, 28 Sep
 2020 15:49:27 -0700 (PDT)
X-Received: by 2002:a2e:7c19:: with SMTP id x25mr232354ljc.376.1601333367321;
        Mon, 28 Sep 2020 15:49:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601333367; cv=none;
        d=google.com; s=arc-20160816;
        b=AFWyPIgA6C7U8odoNPsP3Kc9SnNPFbNRVO4Qgu8N27KYTdV042ZD6AK5dITH7aJR9j
         +qhBD5DLLsPh8gVm6tCTfnfgj2G77rw0NjT2JAWvCT5uYzsdENoWmLVqwp4T+uyv0ZRX
         BM3/95DJb+vBHIkZrdEIWV+R9nP8W24dpB+3S/CuDvQwEqvUJ0XHKn7Zmv/5SafxpjPz
         wQ23tTWm3ohg0WBTNUVBtNB1mif/owEji05+DiwSDRpYGeSjfcngmPaLSyvqQxbINygE
         /7tOEdL0UzmHm+Pusj04ATcibcgyR4SXiOz15g96UjBspVEWwqix7GH4QHKkGpxZRm+L
         NL/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:from:subject:mime-version
         :message-id:date:sender:dkim-signature;
        bh=TAg/M8M9moj9aK9JgpCPViDbJ0zI90Vf31L7QZTXfVA=;
        b=C83sBkW3Bl1Tht1aHyzZKG9wMoMQ0OAKe0IKyMnAXH++Sk4TQmWRTgxlqSG6hbnkgm
         pqGAkAO2yY1YnEguBAoKY2Sxas3liLAjcJwTU5pU3mH3ud4/kppkQGqtMnjR5SRfFy0d
         IU+qlM7BgIJqm2taiL/O6trqw8AsGbwwJEBTGVSKeRecE9pfZQ53bcBcDBk/sjDMaViI
         +C05ytGG3+8tcpMHxO1XLvKJLKcl039XZgcEps2hiioOC/k5XaR5SKzp1BR8p7mmTUsx
         MQIdKNNNZV4mOFlQ26U+CAKavOm9jlVI4QELDACNGj9+YY2ec9A+7ARtgL+rAhDwflNv
         +YPw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WCUoXB1S;
       spf=pass (google.com: domain of 3dmhyxwukcrm2t660z77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--jannh.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3dmhyXwUKCRM2t660z77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--jannh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id f23si205970ljg.8.2020.09.28.15.49.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 28 Sep 2020 15:49:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3dmhyxwukcrm2t660z77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--jannh.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id qn7so995860ejb.15
        for <kasan-dev@googlegroups.com>; Mon, 28 Sep 2020 15:49:27 -0700 (PDT)
Sender: "jannh via sendgmr" <jannh@jannh2.zrh.corp.google.com>
X-Received: from jannh2.zrh.corp.google.com ([2a00:79e0:1b:201:1a60:24ff:fea6:bf44])
 (user=jannh job=sendgmr) by 2002:aa7:d3da:: with SMTP id o26mr221995edr.169.1601333366593;
 Mon, 28 Sep 2020 15:49:26 -0700 (PDT)
Date: Tue, 29 Sep 2020 00:49:16 +0200
Message-Id: <20200928224916.2101563-1-jannh@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.28.0.709.gb0816b6eb0-goog
Subject: [PATCH] objtool: Permit __kasan_check_{read,write} under UACCESS
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
To: Josh Poimboeuf <jpoimboe@redhat.com>, Peter Zijlstra <peterz@infradead.org>
Cc: linux-kernel@vger.kernel.org, x86@kernel.org, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	Dan Williams <dan.j.williams@intel.com>, Tony Luck <tony.luck@intel.com>, 
	Vishal Verma <vishal.l.verma@intel.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=WCUoXB1S;       spf=pass
 (google.com: domain of 3dmhyxwukcrm2t660z77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--jannh.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3dmhyXwUKCRM2t660z77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--jannh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Jann Horn <jannh@google.com>
Reply-To: Jann Horn <jannh@google.com>
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

Building linux-next with JUMP_LABEL=3Dn and KASAN=3Dy, I got this objtool
warning:

arch/x86/lib/copy_mc.o: warning: objtool: copy_mc_to_user()+0x22: call to
__kasan_check_read() with UACCESS enabled

What happens here is that copy_mc_to_user() branches on a static key in a
UACCESS region:

=C2=A0 =C2=A0 =C2=A0 =C2=A0 __uaccess_begin();
=C2=A0 =C2=A0 =C2=A0 =C2=A0 if (static_branch_unlikely(&copy_mc_fragile_key=
))
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 ret =3D copy_mc_fra=
gile(to, from, len);
=C2=A0 =C2=A0 =C2=A0 =C2=A0 ret =3D copy_mc_generic(to, from, len);
=C2=A0 =C2=A0 =C2=A0 =C2=A0 __uaccess_end();

and the !CONFIG_JUMP_LABEL version of static_branch_unlikely() uses
static_key_enabled(), which uses static_key_count(), which uses
atomic_read(), which calls instrument_atomic_read(), which uses
kasan_check_read(), which is __kasan_check_read().

Let's permit these KASAN helpers in UACCESS regions - static keys should
probably work under UACCESS, I think.

Signed-off-by: Jann Horn <jannh@google.com>
---
Calling atomic_read() on a global under UACCESS should probably be fine,
right? The alternative to this patch would be to change
copy_mc_to_user()...

Note that copy_mc_to_user() does not exist in the tip tree yet; it
appeared in commit 0a78de3d4b7b1b80e5c1eead24ce11c4b3cc8791 in the
nvdimm tree.

 tools/objtool/check.c | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/tools/objtool/check.c b/tools/objtool/check.c
index a88fb05242d5..1141a8e26c1e 100644
--- a/tools/objtool/check.c
+++ b/tools/objtool/check.c
@@ -583,6 +583,8 @@ static const char *uaccess_safe_builtin[] =3D {
 	"__asan_store4_noabort",
 	"__asan_store8_noabort",
 	"__asan_store16_noabort",
+	"__kasan_check_read",
+	"__kasan_check_write",
 	/* KASAN in-line */
 	"__asan_report_load_n_noabort",
 	"__asan_report_load1_noabort",

base-commit: 0248dedd12d43035bf53c326633f0610a49d7134
--=20
2.28.0.709.gb0816b6eb0-goog

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20200928224916.2101563-1-jannh%40google.com.
