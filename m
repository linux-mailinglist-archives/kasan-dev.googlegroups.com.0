Return-Path: <kasan-dev+bncBAABBMNX52VAMGQE6VOHPDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id BB6E07F1B56
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 18:47:30 +0100 (CET)
Received: by mail-lf1-x139.google.com with SMTP id 2adb3069b0e04-507bd5f4b2dsf4665354e87.2
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 09:47:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700502450; cv=pass;
        d=google.com; s=arc-20160816;
        b=srE3DzpjIXq3w+eA8aguVctbHnOwGclTLQm4oV69brywZkUCIhceqhRsUT2yxh8ZIb
         ijADzI/ndgfncLo2ilfULQmzTDbs37INdA/O24DjICfR5dSMGRqgnwoZ1FNDaF6UFUfb
         BMmDdU6k32C5z/1G8p3BQcox1NNFhlTXoONOgjpdT4NxI0pBYkuelXgnMxfDQWoe6W0/
         gGd1m01w5auLNlgtLPvjXhBzsh+HHNVgP6snDC6IgssAcirxmGRa3eEmusOIy0fbhzjT
         O6cuAS4Z0rROVKQBjghXE8pILekTrFHDJXpaF8VV3a7oEvG2PCnFX7u7hAnRg+U4blOi
         0JnA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=FTVAWqhuUZlHCzyrxH8q8GBU5Y33gwtTOl1vHDCkMck=;
        fh=qWoxmPN1zRqnLSoCWGpfFsDtzJsx/SGdqx98lbP+Uho=;
        b=s2a0+9EbEX+HqRpKX/fAWvz4BI+YUds+zqXLC0/CD0l9Q/r+3t1gWPTxQS/s47R4VT
         cjaSg8sxFoZp7v8aiD95PZkkPT4AxkodHwVvIIy30Crvz7YgCmNo3YSJXBAiT988QOJr
         j/g9/mKe3cwlXzVNDYr2sA2HF/jDtFmimwbP3qsMD1j13kQeqHeDl5vU6trFwpR/oj4x
         I8jju2rhyxMeM7/5D1RIr9UMoalDofWfHt3TWqfIbVOz3Wuz5DquKohxei59Be5J08qt
         NTjAl/TwOUTYTIEUtWH7u2Y5c27ryJnTtgbWnoGmUd8fi4FZYwO66vJhFlgGUfckC+t8
         nu8A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=qyhdPL9y;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.173 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700502450; x=1701107250; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=FTVAWqhuUZlHCzyrxH8q8GBU5Y33gwtTOl1vHDCkMck=;
        b=Y9TPfodlnmVwyseDl2kLXqojlSW1Ad8kiZetpczwkUqY8KK5eei7J8+PmjfmhsXoow
         Nc1m52Wff3sh9xwNKjPSfzfXKvtdC0RVjjWUJHpwRPq9D94n3eQonLjr+KcXTlYV2Yeq
         lj6I0ahAp7BX25ofnCnKatr7DqeoODd/AjHI4ew2fqdn50m1tufIhie7s27evkc+szqm
         H+tfTX9LV9aXjprTM4mx0cPXKWc40js3NUEpml4I64O/vXi1IOd9Xea3adkpg/qwwyn0
         endS3lcCP3sSXUu/TyE3SO9BvIK+cou93qoAfYtoWOL2cWDks2KHXje0b8qb6nMybJL9
         4PwQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700502450; x=1701107250;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=FTVAWqhuUZlHCzyrxH8q8GBU5Y33gwtTOl1vHDCkMck=;
        b=aMW6j2gc+Vqjf2LR2nBayDzYhLbxu4fnwVNWHofijE6x9n9j3utAhg/ML6p3wc4qO0
         F/s0tk/twXPEKXAvfSJq/1blH8kqxaJ5CkvCEB+R5/Bxold6sGWClwXBymveByVnN2oo
         ke/DWWf69pbjVuHq4KQA6E5NRg7WJbuLZn0wKWEzdhyewdt4sRNqIJw4QkmE9dL43157
         8xUFJ/NKhU5Wx2FinLjWUNCaYDXHRxriodOBpS/KId/smu9PkyanrJAzlBH41/L+darw
         weic50aOHKErVhB9QKNUasXkLqNj206jJSQFudxjaQIglfF8gDMEu+PPO6VxOXWAz1ic
         nG/Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxGHNAGOa7kL4mnasxHtaCljc14DFCRLiYzP8fFzcn8cFaKIXF4
	fV2+TGkzdu7MqHGWFP7QM3Q=
X-Google-Smtp-Source: AGHT+IGxnVPM92Kt/9Xl5VSHQozHyMuNHkwT+W+7zzQ/5VBjBMdDwoCLwdGDylq81WxZ2tI5scfzpg==
X-Received: by 2002:ac2:44b3:0:b0:503:28cb:c087 with SMTP id c19-20020ac244b3000000b0050328cbc087mr5922884lfm.29.1700502449975;
        Mon, 20 Nov 2023 09:47:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:e9e:b0:50a:a999:f190 with SMTP id
 bi30-20020a0565120e9e00b0050aa999f190ls91079lfb.1.-pod-prod-06-eu; Mon, 20
 Nov 2023 09:47:28 -0800 (PST)
X-Received: by 2002:a05:651c:1a24:b0:2c5:db3:d3a6 with SMTP id by36-20020a05651c1a2400b002c50db3d3a6mr6223814ljb.19.1700502448339;
        Mon, 20 Nov 2023 09:47:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700502448; cv=none;
        d=google.com; s=arc-20160816;
        b=g34BKzKRang3QoQlInF8K7ntp3nXquPz0BK0b9kENBlKaWdLmWsfd6K8PmqDV3ivIn
         jfiXSGmUXgLsrIc5id2CL+dB/V+wD+C1FHXXWWIjSuiLbzGXQqnGa1Zaj15tDiivPOvI
         HSRFU+J5nlUkibrqTaTnrXQ/WkqLJknZWSHmcDGG5Y30RXCIOeiujV5Q6EltQqN8gDjX
         GkXUsvJBtR1ktHPX/T/DKHAO/kmxCkTbLQtAcZ6dhsy3Ak7m6ceVWidY931NMjsrTpxY
         CSNGS5KhpNr/nWcYx8W8I3Wnq1vEonK16VVS7sV5Rhx+QYoHbM7uJ1WGHPh6mZAzh7GO
         Mvxg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=4GD92F9WT2lJ15sdFM57D7OnzHXCVz8Opyiuivl9/aY=;
        fh=qWoxmPN1zRqnLSoCWGpfFsDtzJsx/SGdqx98lbP+Uho=;
        b=qX4Sg1bsMAem8lY/EIButJ+ne1Ib97plGTUdV375KCVhJhhvH0OQDvS9ixifA2brMs
         eWdK6X0CGMEae+XT1zdAKGcItSoJrx3mk6xIQe4kKWISaLe71FojMb6db41+N5+FBn1h
         XP7a43FtmJuNAZSZU0UpOb37Ak+q3RflJZKZ0A+9TQYwOM5Y+4tHI5Y1azDZLnBojboB
         Fudg4I4DFtNLq+6FU7/n+AErhwWhRDP5u4l3uwTHg/Ag1lSOpBxQdnalj/cNJVE2aonk
         QcuiCotNxwnV9vBw8IM+4jg8F6tK0oQ5aIYAJoBKiVEgqwBeO1MFLJzvJ3Emuq2m8rfk
         eyLg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=qyhdPL9y;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.173 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-173.mta1.migadu.com (out-173.mta1.migadu.com. [95.215.58.173])
        by gmr-mx.google.com with ESMTPS id m32-20020a05600c3b2000b0040a42c24845si490577wms.1.2023.11.20.09.47.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 20 Nov 2023 09:47:28 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.173 as permitted sender) client-ip=95.215.58.173;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Oscar Salvador <osalvador@suse.de>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v4 02/22] lib/stackdepot: check disabled flag when fetching
Date: Mon, 20 Nov 2023 18:47:00 +0100
Message-Id: <c3bfa3b7ab00b2e48ab75a3fbb9c67555777cb08.1700502145.git.andreyknvl@google.com>
In-Reply-To: <cover.1700502145.git.andreyknvl@google.com>
References: <cover.1700502145.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=qyhdPL9y;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.173 as
 permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Andrey Konovalov <andreyknvl@google.com>

Do not try fetching a stack trace from the stack depot if the
stack_depot_disabled flag is enabled.

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/stackdepot.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 0eeaef4f2523..f8a8033e1dc8 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -483,7 +483,7 @@ unsigned int stack_depot_fetch(depot_stack_handle_t handle,
 	 */
 	kmsan_unpoison_memory(entries, sizeof(*entries));
 
-	if (!handle)
+	if (!handle || stack_depot_disabled)
 		return 0;
 
 	if (parts.pool_index > pool_index_cached) {
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c3bfa3b7ab00b2e48ab75a3fbb9c67555777cb08.1700502145.git.andreyknvl%40google.com.
