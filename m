Return-Path: <kasan-dev+bncBC7OD3FKWUERB365X6RAMGQES6HV5DQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x938.google.com (mail-ua1-x938.google.com [IPv6:2607:f8b0:4864:20::938])
	by mail.lfdr.de (Postfix) with ESMTPS id D15006F33B3
	for <lists+kasan-dev@lfdr.de>; Mon,  1 May 2023 18:55:12 +0200 (CEST)
Received: by mail-ua1-x938.google.com with SMTP id a1e0cc1a2514c-772cb9bedeasf935574241.1
        for <lists+kasan-dev@lfdr.de>; Mon, 01 May 2023 09:55:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1682960111; cv=pass;
        d=google.com; s=arc-20160816;
        b=sOpPIytgR6Jw/glocOkESjLsk6t0Gyczk6XF/KdujJqnXtpYYwjzBhrJkjWCqJgL/Z
         UgqLmitzSRGCjJIx3dPPLJ1SAWQLuNW8bxoTxrazjgoXY0IDxtQlrnEZjQtrQJAVVR9X
         eM4rcmfMNSyvjUAq+U2ffV18k4GjUWTo0Av0pxakk/SxWKxcK34okqX3uEURzKWGfnZT
         /981iNuFsQNNCi6xQ2CnRZXe1PVnBFcpn3oqkCkcj+lIjhoUkyd366cZ31AGFZLEcO4J
         l79KbHjTr/RJugA4fTewwnD3RDzzBR6tXSwCdVeTQCQBYKpQSqnerTerQhp4UkYozqAj
         bT3w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=VWvpp0jD8QbO70dt1dptVj3xNsBMR+50dkIAmWHmzsk=;
        b=0KYRCG9pLgFdOIp1PYTwoCrLSuurOTpp9IUjHnRtT8i64W1QO+Sk8PUvYTFOjDZVfP
         8j0KmlLgNWgzupTS7TZwspcLTyuGmBgfwdX7XBjU4yfRSQHuEl66nPp9M+am10vb/uoK
         7IeA3DEGwPdJ2kr04Z6D81t14G41X8QaqR2jDMl/+YUxQRMcf1wwkLmnPVbmjqsHQkkp
         WsLaNHSsZIpmsjT6xgWADuNNxILdbCUkUf1sox4xQMO3ioFYWUwd5rp/EpphOQ/yDxa2
         zLFEA4pb0ZXyayAQ2YCpF5QYVUtoc14ZZ6FPzGoEaoO3I0vmu19nkeL1kYbAj8JhSkM+
         35xA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=2YKjiLNW;
       spf=pass (google.com: domain of 37e5pzaykctqikhudrweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::104a as permitted sender) smtp.mailfrom=37e5PZAYKCTQikhUdRWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1682960111; x=1685552111;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:from:subject:message-id:references
         :mime-version:in-reply-to:date:from:to:cc:subject:date:message-id
         :reply-to;
        bh=VWvpp0jD8QbO70dt1dptVj3xNsBMR+50dkIAmWHmzsk=;
        b=m6nODHUnPslDyhrn4DNSdfi44lG8vGWmRhPs0JuxTv80n+0jyfwypyfZ0H2Jugd5hs
         r+wXkKFwaajOTlT0Csp8hvg6zQnDfsp1u4sKuQGcQMaTWYgmpsbm3VW0q/8vZj9ImnOv
         su7oxcySKMPv1yM3xke0A8VJTdflbKp7gSt1yg6315lskWIzyxJcLPe1tB60yZql7yLK
         61iUKWy8CrGzHIeMasRXihpXIt5Ubo5I/jOkwywA46AlzQBLBUwQhTsATYSWBI9+Ogud
         Wv0bGsAjVtI45p0es4qP9UGghgkn6ZWjuS9mjjbSEyt39OZoBzE5neTvEpF0T5MfcWNl
         2hMQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1682960111; x=1685552111;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:from:subject:message-id:references
         :mime-version:in-reply-to:date:x-beenthere:x-gm-message-state:from
         :to:cc:subject:date:message-id:reply-to;
        bh=VWvpp0jD8QbO70dt1dptVj3xNsBMR+50dkIAmWHmzsk=;
        b=eS2EQTIk2nLFeGi/ANBeuN+6Je1ZrW7u4O58DZUhe+JY/qAXB4qOtAWMjWC90E/54e
         vaoavK7ze7HhrHuDcdjJ5t2DHApYPGV3sBcfP1gsKJ8M8cZ+4311sTNfetnXaV6VkyvV
         ez4eSPfumDKR6uVKc0/ynPxvoALAfF1hqYzxWqeXDNZme3A5aFlmMa45arFC+r92buun
         c3z4becixnhTu2lCypJEfCM4lz3C47/dM8vvha1ZPOSlKaVkePEIGhXcJLA5CZbLAe32
         LgSakvMFVVEGURJqOsWVzuOxDfSWA1EAiPRxG6+dJzJB3spSAyz6CSCqtsRcCxnBx1gC
         ojyA==
X-Gm-Message-State: AC+VfDzyIyYEoTBZq4/0oO+P3mntvPnLEigLP/RtyhaDOzMImI32EkEo
	fSdQoPJYj7yfx79TdBhqRXE=
X-Google-Smtp-Source: ACHHUZ6waK8omx441UC7Q6pyXHPoUQBh/Mhq5uTeo/yN+SmSPf2Qd/5o7dTDQCtImYvRtbaRQz7xdQ==
X-Received: by 2002:ab0:31cc:0:b0:77a:6db9:1516 with SMTP id e12-20020ab031cc000000b0077a6db91516mr6669005uan.2.1682960111548;
        Mon, 01 May 2023 09:55:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6122:2001:b0:44a:fd79:c66e with SMTP id
 l1-20020a056122200100b0044afd79c66els1221261vkd.4.-pod-prod-gmail; Mon, 01
 May 2023 09:55:10 -0700 (PDT)
X-Received: by 2002:a1f:c110:0:b0:44b:5375:5a25 with SMTP id r16-20020a1fc110000000b0044b53755a25mr3654558vkf.11.1682960110866;
        Mon, 01 May 2023 09:55:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1682960110; cv=none;
        d=google.com; s=arc-20160816;
        b=YMd4OfFNurypmkhsRjxWe4q1l0ReCuATuuEkO/j+Uy9G2uAd4hP+xQjWlXB7+FvzH+
         gl/gAlRon8eKIWLZ9sy2LWFn+QpiupWsCDFZV4DVj9VDBQbkQe+XLtaDtNAR/qGlgHPC
         fKtJzUlGmjkvHUholn53CZLd1OkZrV6npNifopGS39tgXOKxLTc5Mt05jS/OK1DAQ2VA
         EqUeSDV/2zBF7UUNnV+Ycg87nY06C5Q/Or+BdR6KvhmoAQD9q2nPbczBsjJpOiEsp24t
         +PN6iOLI34SXm094dTVuXoibGeOVdZMFq3jsAPEdG68og9PL7CrkDQytItOwBo4ZIb5D
         WEww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:from:subject:message-id:references
         :mime-version:in-reply-to:date:dkim-signature;
        bh=tgVoyGNNM2CEwgGlnNhwRO5zW+BCSfKlhykn/JkHIoY=;
        b=O0++kVrSum0EsfI7bKh7WSkrdG8KgFNGiFwLugs4hgFkGR+RJPaBhFdrYBNSmLXfSn
         xf6/rM0Gs9FdoSjjGFIZLtjY78lkqcCoY/qXrs9X9yWZH36nq20LmO0m8rcmDsuFRnVz
         AH8ReFwXWk9BlpUoDGMCRyF9DoSsBeJu28dTWaklUP8K/VR1kpJZ1MHcxJiw2F4E43w8
         eaCpIHRKnwg/n7tCiNRY1velaHQCs5uzlzgPMiJwWsDK9Mo8KndiyvaGV73rruXzmrrT
         c+geC1JzLbaoT0nKfgPxC8gmMJoqHElJ7oaklawcqMOTHn/om4Ipe6UROnTxNioLcQXy
         ixQA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=2YKjiLNW;
       spf=pass (google.com: domain of 37e5pzaykctqikhudrweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::104a as permitted sender) smtp.mailfrom=37e5PZAYKCTQikhUdRWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x104a.google.com (mail-pj1-x104a.google.com. [2607:f8b0:4864:20::104a])
        by gmr-mx.google.com with ESMTPS id n190-20020a1f72c7000000b00443e9a2bf3esi1794836vkc.2.2023.05.01.09.55.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 01 May 2023 09:55:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of 37e5pzaykctqikhudrweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::104a as permitted sender) client-ip=2607:f8b0:4864:20::104a;
Received: by mail-pj1-x104a.google.com with SMTP id 98e67ed59e1d1-24df9b0ed7aso1439415a91.3
        for <kasan-dev@googlegroups.com>; Mon, 01 May 2023 09:55:10 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:6d24:3efd:facc:7ac4])
 (user=surenb job=sendgmr) by 2002:a17:90a:390d:b0:246:66d6:f24e with SMTP id
 y13-20020a17090a390d00b0024666d6f24emr3850182pjb.2.1682960109840; Mon, 01 May
 2023 09:55:09 -0700 (PDT)
Date: Mon,  1 May 2023 09:54:11 -0700
In-Reply-To: <20230501165450.15352-1-surenb@google.com>
Mime-Version: 1.0
References: <20230501165450.15352-1-surenb@google.com>
X-Mailer: git-send-email 2.40.1.495.gc816e09b53d-goog
Message-ID: <20230501165450.15352-2-surenb@google.com>
Subject: [PATCH 01/40] lib/string_helpers: Drop space in string_get_size's output
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
To: akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, ldufour@linux.ibm.com, catalin.marinas@arm.com, 
	will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, 
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org, 
	ndesaulniers@google.com, gregkh@linuxfoundation.org, ebiggers@google.com, 
	ytcoode@gmail.com, vincent.guittot@linaro.org, dietmar.eggemann@arm.com, 
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com, 
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org, iamjoonsoo.kim@lge.com, 
	42.hyeyoo@gmail.com, glider@google.com, elver@google.com, dvyukov@google.com, 
	shakeelb@google.com, songmuchun@bytedance.com, jbaron@akamai.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	surenb@google.com, kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org, Andy Shevchenko <andy@kernel.org>, 
	Michael Ellerman <mpe@ellerman.id.au>, Benjamin Herrenschmidt <benh@kernel.crashing.org>, 
	Paul Mackerras <paulus@samba.org>, "Michael S. Tsirkin" <mst@redhat.com>, Jason Wang <jasowang@redhat.com>, 
	"=?UTF-8?q?Noralf=20Tr=C3=B8nnes?=" <noralf@tronnes.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=2YKjiLNW;       spf=pass
 (google.com: domain of 37e5pzaykctqikhudrweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::104a as permitted sender) smtp.mailfrom=37e5PZAYKCTQikhUdRWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--surenb.bounces.google.com;
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
Signed-off-by: Suren Baghdasaryan <surenb@google.com>
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
index 230020a2e076..593b29fece32 100644
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
2.40.1.495.gc816e09b53d-goog

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20230501165450.15352-2-surenb%40google.com.
