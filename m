Return-Path: <kasan-dev+bncBC7OD3FKWUERB2ULXKMAMGQEZMEY44A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33a.google.com (mail-ot1-x33a.google.com [IPv6:2607:f8b0:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id BF4435A6F79
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Aug 2022 23:49:31 +0200 (CEST)
Received: by mail-ot1-x33a.google.com with SMTP id m15-20020a0568301e6f00b0063729bd5c3esf6583706otr.1
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Aug 2022 14:49:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661896170; cv=pass;
        d=google.com; s=arc-20160816;
        b=uZXBaN+5OqTkueGPiKsx48R1Z71SleaMtmHXPhbp0CHb3Oy7dMGNq2ny5UqBoCdBxR
         rEukS4Gx+H1WfSfCKTM3F/F6CcyBU69W8TkgeyewrAVXFX5tYV6I4gVS84s7y33dYQr2
         GUymMpXjifZyTtytqjepSkMp9iX6IroJu3FV4v3SGbkkZ7INWRZCxhqxeWyy7VTEMZBG
         2fnKWsiC2uHNs8bdaKuRnxMIeOuFYGaMfXPgI7mrFQGA6LuDEpoVS2ySNhVVldAthkzk
         xvymhSUuGx4cqd0LKzvoD6KjPICaDETlreJlLvjx9HXu2/gCx67LCvLcU2jFKKWSxalr
         Aw/A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=Cpnvxe1M/OY5FgTVa2Sz2eGolHfFFZ0vXGMYN4252E8=;
        b=gGqeaE4PYPfzyfTuPhSlOGW6Hj7PADXQYCPzc2P3YpmoW1mQqA4M9Rs+GuHvBRA6Ck
         biffpcqCmtqLCWpMEwVRZhc3u8YVcdSehyKQxKBiJz0kZ1SBk9w8rqkaXDYOMuocQ9Yu
         FK5JXjp5bYALQ2qK/rpl6NHOsxRGvLngxmsvKeyZCOgLFNJbg2kHXWWhPBLEkBoExHkE
         AYG3wCYxdPY2pNm9A8UtwhwkRs/bhEsf85L/WhxXpbsQBRvGkd9D0ETeIQWRaiEDWjZG
         Rrk95QkW5dkrl2i0IBlN205T8p+1AP3T0bJ0JDOU5YqZD29KgnPSf5p/x4wV95EAPsJq
         1zqA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=kJlmMVVb;
       spf=pass (google.com: domain of 36yuoywykcu48a7u3rw44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=36YUOYwYKCU48A7u3rw44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:from:subject:message-id:references
         :mime-version:in-reply-to:date:from:to:cc;
        bh=Cpnvxe1M/OY5FgTVa2Sz2eGolHfFFZ0vXGMYN4252E8=;
        b=pkg/94RUuNsVTmsGKA9PpskEuy2f/FeZNEGHUz+PIkGoAZAFFBvw02HEQBUVL8xO8B
         EESjWHBMDo++cWqUmNLK3yZc1H4lAkkST2ErbxthKUM7jUuBQHVgVs8xaIYiTNqnfqpB
         jjvg20qs0VkYuloYb3Ovvxdbqr+zdu5K2QqsOy6QY2fsIzbA8ME5QuRuzaZgNBp5REKD
         achQBT9r2jiwOhIzpFhHpJx7nM9uhmXe7H0J/+zuq48TYm2A+Ic6kg16B4/hnUSORL9r
         HLqQ8tmnU6GnnzfuKFcr/xExyKeGNVNFon7xrujdW0sI0Gr2RMg8QN/vEAhIRBT6T3WJ
         f7ZQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:from:subject:message-id:references
         :mime-version:in-reply-to:date:x-gm-message-state:from:to:cc;
        bh=Cpnvxe1M/OY5FgTVa2Sz2eGolHfFFZ0vXGMYN4252E8=;
        b=KtDGB9q8NURSvcZSiMtHJduXZkB0xND5r56PZcU/Bj+r70PTkefd9rShRJJVWjiBpB
         2NvxpFWUwOpdNwnin96ufftBYRuCu1Luu0ahoB6U/KJ5TfuahhFGpaoTU2880sracvnh
         UsV0WM7FD5LZy9fgfU2OJgsrICCWVAG7m/tOWMlhUYA00ac47BK8x4ClEK1uuyRz06CW
         ESu+Hbxw2KchVbc77ZM9IdySkiubTF4DaQaX6SJm5jAcO7EB2woeUnSnd9bFdF8YXkQl
         55f97fqA5Ac1+gSmSxGhKsyGbDkE6eWc90zvtTzYrUrDWHChv9s24ty6TF855KDZZa+h
         vXSw==
X-Gm-Message-State: ACgBeo0eY35Shi7DsxJehSMXuZOu/wL+jX/uY+8BNAp50a2Mt1iSCqaN
	PAVrYVIZn4c4NLveIrq6oIQ=
X-Google-Smtp-Source: AA6agR5ZiBmJSBljb6leA3RvcugWsom8fACpYBKq6ABFs3rv6qBpKpV9cFvz6mZZn9jDpQ3TgJ9/JQ==
X-Received: by 2002:a05:6808:14d6:b0:343:4972:bd09 with SMTP id f22-20020a05680814d600b003434972bd09mr28170oiw.180.1661896170349;
        Tue, 30 Aug 2022 14:49:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:3491:b0:11e:4261:68e3 with SMTP id
 n17-20020a056870349100b0011e426168e3ls4207215oah.6.-pod-prod-gmail; Tue, 30
 Aug 2022 14:49:30 -0700 (PDT)
X-Received: by 2002:a05:6870:a2ca:b0:11d:577f:540a with SMTP id w10-20020a056870a2ca00b0011d577f540amr12009oak.223.1661896169931;
        Tue, 30 Aug 2022 14:49:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661896169; cv=none;
        d=google.com; s=arc-20160816;
        b=xgax3K//J51xjTcGek5b4wGZwXZ+YUrjiCsxByQyQ+b2NJ+uHVSkSI8ONBA9Aut22i
         CIlCwmycAdhSN5gtHNNnN/c7Z+aipwsAOVhrWuemdGGEYJmlqWMAbe8G7dy6vfLoB7dj
         ilHNPyRS9iHAyq1MWsTe0rQo0WYJ9njbyN/+jvs2KpcvJTb0/OGrlPXueig7ZBWaBKda
         uSQSSGyKJ6UItdP29bnmiTQ/U/C3PBX53AF1VI09lftD90rXpCCxpZfqEu5Pkr5E5h6I
         iyuU4WqBNwy8hybj3gteXGaCs4ouFW9oN8cDa4IQb3AcHT34oZsJAowQODlr2vH1oTWe
         h1EA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:from:subject:message-id:references
         :mime-version:in-reply-to:date:dkim-signature;
        bh=nkzMCqKgjBTn+NwznXGF4FkMKBv5sNXeON2LIxVXB6M=;
        b=LfT+prb0m/JyCqlAD9aISajVdU9H7qjBr3Y8nrSEPdQLeYxnVHV4QgDEKrDsdMu4T4
         g7dghUS5Uw1EDq37z85AjHvG/57VWIGtUD1CjCmO+ZSshJ8rGSLV9RZ+dRJL2keHtzlX
         yzj5iRJ/80d/vdSPsSNbxvVQRLGAUpHTjwNeCNXUAVVCpdIhYJyNNxtFNc9valy1NXq7
         OBzU4Rmn6FBWgmDznsU+ZaKXx/e8ug9OOb+92Up2i4EQzAE+GgIPIOL/w33dgfbZh6+J
         HZPLjX2/QhlcMvXwUdQV9uUvcpfcJBbEWJWr4ov8Tr4vZ9R3E2O5d+Q7l8ahsumqYnpM
         Hb9g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=kJlmMVVb;
       spf=pass (google.com: domain of 36yuoywykcu48a7u3rw44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=36YUOYwYKCU48A7u3rw44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id z42-20020a056870462a00b0011c14eefa66si1291559oao.5.2022.08.30.14.49.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Aug 2022 14:49:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of 36yuoywykcu48a7u3rw44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id d8-20020a25bc48000000b00680651cf051so724022ybk.23
        for <kasan-dev@googlegroups.com>; Tue, 30 Aug 2022 14:49:29 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:200:a005:55b3:6c26:b3e4])
 (user=surenb job=sendgmr) by 2002:a25:e90e:0:b0:695:64cf:5d2 with SMTP id
 n14-20020a25e90e000000b0069564cf05d2mr12975575ybd.541.1661896169455; Tue, 30
 Aug 2022 14:49:29 -0700 (PDT)
Date: Tue, 30 Aug 2022 14:48:51 -0700
In-Reply-To: <20220830214919.53220-1-surenb@google.com>
Mime-Version: 1.0
References: <20220830214919.53220-1-surenb@google.com>
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220830214919.53220-3-surenb@google.com>
Subject: [RFC PATCH 02/30] lib/string_helpers: Drop space in string_get_size's output
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
To: akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com, 
	ldufour@linux.ibm.com, peterx@redhat.com, david@redhat.com, axboe@kernel.dk, 
	mcgrof@kernel.org, masahiroy@kernel.org, nathan@kernel.org, 
	changbin.du@intel.com, ytcoode@gmail.com, vincent.guittot@linaro.org, 
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com, 
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org, 
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com, 
	elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, arnd@arndb.de, jbaron@akamai.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	surenb@google.com, kernel-team@android.com, linux-mm@kvack.org, 
	iommu@lists.linux.dev, kasan-dev@googlegroups.com, io-uring@vger.kernel.org, 
	linux-arch@vger.kernel.org, xen-devel@lists.xenproject.org, 
	linux-bcache@vger.kernel.org, linux-modules@vger.kernel.org, 
	linux-kernel@vger.kernel.org, Andy Shevchenko <andy@kernel.org>, 
	Michael Ellerman <mpe@ellerman.id.au>, Benjamin Herrenschmidt <benh@kernel.crashing.org>, 
	Paul Mackerras <paulus@samba.org>, "Michael S. Tsirkin" <mst@redhat.com>, Jason Wang <jasowang@redhat.com>, 
	"=?UTF-8?q?Noralf=20Tr=C3=B8nnes?=" <noralf@tronnes.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=kJlmMVVb;       spf=pass
 (google.com: domain of 36yuoywykcu48a7u3rw44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=36YUOYwYKCU48A7u3rw44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Suren Baghdasaryan <surenb@google.com>
Reply-To: Suren Baghdasaryan <surenb@google.com>
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

From: Kent Overstreet <kent.overstreet@linux.dev>

Previously, string_get_size() outputted a space between the number and
the units, i.e.
  9.88 MiB

This changes it to
  9.88MiB

which allows it to be parsed correctly by the 'sort -h' command.

Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
Cc: Andy Shevchenko <andy@kernel.org>
Cc: Michael Ellerman <mpe@ellerman.id.au>
Cc: Benjamin Herrenschmidt <benh@kernel.crashing.org>
Cc: Paul Mackerras <paulus@samba.org>
Cc: "Michael S. Tsirkin" <mst@redhat.com>
Cc: Jason Wang <jasowang@redhat.com>
Cc: "Noralf Tr=C3=B8nnes" <noralf@tronnes.org>
Cc: Jens Axboe <axboe@kernel.dk>
---
 lib/string_helpers.c | 3 +--
 1 file changed, 1 insertion(+), 2 deletions(-)

diff --git a/lib/string_helpers.c b/lib/string_helpers.c
index 5ed3beb066e6..3032d1b04ca3 100644
--- a/lib/string_helpers.c
+++ b/lib/string_helpers.c
@@ -126,8 +126,7 @@ void string_get_size(u64 size, u64 blk_size, const enum=
 string_size_units units,
 	else
 		unit =3D units_str[units][i];
=20
-	snprintf(buf, len, "%u%s %s", (u32)size,
-		 tmp, unit);
+	snprintf(buf, len, "%u%s%s", (u32)size, tmp, unit);
 }
 EXPORT_SYMBOL(string_get_size);
=20
--=20
2.37.2.672.g94769d06f0-goog

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20220830214919.53220-3-surenb%40google.com.
