Return-Path: <kasan-dev+bncBAABBNNY52VAMGQE6YXTZEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 3E0EA7F1B7B
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 18:49:42 +0100 (CET)
Received: by mail-lj1-x239.google.com with SMTP id 38308e7fff4ca-2c50d73e212sf39884281fa.1
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 09:49:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700502581; cv=pass;
        d=google.com; s=arc-20160816;
        b=PeNXnUF6iDnUBi3p9SA9GCWtSDpupcd4wgxPbuGihMfo3fHX5bg7kikLbItUUxZoda
         5WL+uS2sf08SQ9Br8B9JCROPcZTjZWqs6eR2Cg1yxp5LiYWA9GJimPDjoXQeTKkCsO9r
         BYsNFwCfuJVgHpK3eUAYkX9q6dMna03FaZl1DNDK02KiJhuRg8W9z6Af89bady0fMnlM
         KBcs4ga0SRcOh7ansvNr7bkqv+AS2Y8qk2pBg+BJVVnGhJ3woJG5UWQOSjDYMnx3CbY1
         X4FMZY6gyuc5oKxXKiTwEmxXFjA8v3kALp85iLcdaC65GgSYypPSuglTsTmdbDkwWs88
         3q/A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=CvbFBXOSQDq0LVuA8hmnTfSnDAndVfdCGMnCrAOl+So=;
        fh=qWoxmPN1zRqnLSoCWGpfFsDtzJsx/SGdqx98lbP+Uho=;
        b=y5EMo1OJpNmdNtanSr20IFgb+P8gmlpkwX9Bij1m3aFBadwcZ7DF8Cigx4CI4GLWox
         pEDq9iu5un28yWBHfZnMYK3cRw2aAP+FkbHZTA7LhW64SavRPadLvNFbETRMnwLrJHCg
         uRv5Sz1HByQbkpTs0BJ0kc9k+caWsB0oFlIQTPbzf3Waiv3rgVGy7WPxUYGyMosbaCAQ
         h+NZARGsrO2oQ2NjcTlBgzjun2d/bZxyFd0yfcje7+VZ5IOn6YngoGWMQcwvN8PBhoBv
         PttXVloHPHQbD47cmtQxNHVnaO4+DBGNNP/FPzkUXovsE8koXKiMDcykmqr6IPPBuY/j
         dg2g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=b2OIEP3B;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::b8 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700502581; x=1701107381; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=CvbFBXOSQDq0LVuA8hmnTfSnDAndVfdCGMnCrAOl+So=;
        b=HL2dBff2Q7xp5ASWsOOh+7qyq21SzxClgQ0i2nlaoL83hAOIFttVr72hs8QAKYIbmY
         FLcOpGpfYIUHqp2x3m6iwKoX7dwrCl/VbS08rn/ROvalHwyLWwmg47DJVgLTs4N/G3bX
         KBlII9HOAccoO3QYoUoqA7GDA7iencoynd4Ov3P1Qb/8I4JeSzBtp9u03dVyCvBGLz1L
         p8JkX0WYkrOQ2NX7mpGb7Cb8Hnh5N2bb/4dLCrOfmwhK6xviyPmcsT5GZzkuO19EMD3d
         aWLmCnj2nZEq55nUPAb/vkVgNt8iMZ8Jl7HUL+i8rFWJDcdkKEB9k1SpUneA7+hBs8c/
         NIng==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700502581; x=1701107381;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=CvbFBXOSQDq0LVuA8hmnTfSnDAndVfdCGMnCrAOl+So=;
        b=WWTzuiQzzWIdzVtdIzaW1Pf7XoY0S3SzdUS0Nr+sMZeH/LYz7QxeNcUwjSqDGv9Om5
         wauQ9XAeEeRbm7d4IF4ZMXTJlUSIOieE+D/ARYJl9Vbph2P/+qWhQOKs01ZzP1AieiON
         39oeIS1EvOS1Ko0R+UytO+Ax0EH9Yfu6/dxk1hgJGCBMdTMqxJmaCYTggM41MyBJKxtU
         ZRKcPMaMGytPWjDpP8iYocjxFuWUiN+kohIVSNQcInqOPoSNErdSTn1H6nRvW+8xK2Kh
         s8XVAQWtUD3PD7f2vi+huwxFHVq97jAHPRV05PzxaTzpFC4vnqEVBe+07kkBQUadmaa5
         KPdA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxiDtV823YqTnfcFsRtz/OqxSjeql4p40BtGdogDUU4LcRbbcbE
	h/aIzWm5nYZr1Og67T4GOhE=
X-Google-Smtp-Source: AGHT+IFgivyUIL6qoUQNTdsBrOzTH7jhGccZrelWTt7Onie4e6K2Vy8ET41/4viIPTIRnhhaFULMPA==
X-Received: by 2002:a2e:7c0d:0:b0:2c7:8fee:c295 with SMTP id x13-20020a2e7c0d000000b002c78feec295mr5287638ljc.42.1700502581356;
        Mon, 20 Nov 2023 09:49:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1181:b0:2be:58d1:dc38 with SMTP id
 w1-20020a05651c118100b002be58d1dc38ls103454ljo.1.-pod-prod-06-eu; Mon, 20 Nov
 2023 09:49:40 -0800 (PST)
X-Received: by 2002:ac2:5203:0:b0:502:cc8d:f20a with SMTP id a3-20020ac25203000000b00502cc8df20amr6053630lfl.27.1700502579671;
        Mon, 20 Nov 2023 09:49:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700502579; cv=none;
        d=google.com; s=arc-20160816;
        b=sLvk3aulHYfXk/aAFg50TLhGjHrrPvLU+XrZkC+m5grBPx5iQFg2JJA37DMzWnumM7
         eOn1zi7auQpfBDtVPu5R2nZhM6ydTuydgUSko4BVup1Iar70QuqOh9yeEtGTjUDpP4Qm
         wyZf18dC9j/Mxs1PY6tAqqay7wrvdj43YM+1WYxeSMpf1AUL3n4R19KhlxExUVaAZDKc
         Rpw/Pi2TpwDZ4sg5Jd8qAPUx6qopj+HmxL+QINb9J7NR163d4eMjN7IBUim9e8HRIqaC
         6htALbDLaUiUMZ3FXjtwhW9DHH1pvwAuCIs0gLo7DstC1QVnl7Bah5vtE1e3c3JGQwc3
         ylmg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=AmubiAZbFJ0d/i3HqBc+VhVD2T8fru9oX5DWKdU3rlA=;
        fh=qWoxmPN1zRqnLSoCWGpfFsDtzJsx/SGdqx98lbP+Uho=;
        b=ekjEyr7P/82ljoGXBUVNh3rgx7jPoqpVuD0t56GMkSqUyYXSw3pBD4kwuSOYfpYncV
         txFxu/jBZ+IgFOboV+mrV9OKubP8M0E73cmfY1/sTZ28CV7gU/8ObScl7AMRjUCU2Dl/
         HdBZPNx3VJ3Y4BY+CUGp/M6dBz0ojVIec5+j4URgYZjhZEYt5euyAGQBgOqv/4gf8e6U
         GXVWcGI5qMCGIs+MEccVHNQRRaZREikSfaWHC8fehRtmplXo3qMb8yPZX2jmtDgDOV2/
         HyGr6Agfujw+SL3PO6vVY7FnNOjFJzXLpDAInyAIRxTQEpDrEdZe+qe+wpHeJmsyBC4u
         Tk9w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=b2OIEP3B;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::b8 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-184.mta0.migadu.com (out-184.mta0.migadu.com. [2001:41d0:1004:224b::b8])
        by gmr-mx.google.com with ESMTPS id o12-20020ac24c4c000000b005056618eed7si295644lfk.4.2023.11.20.09.49.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 20 Nov 2023 09:49:39 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::b8 as permitted sender) client-ip=2001:41d0:1004:224b::b8;
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
Subject: [PATCH v4 14/22] kmsan: use stack_depot_save instead of __stack_depot_save
Date: Mon, 20 Nov 2023 18:47:12 +0100
Message-Id: <18092240699efdc6acd78b51e41ea782953e6c8d.1700502145.git.andreyknvl@google.com>
In-Reply-To: <cover.1700502145.git.andreyknvl@google.com>
References: <cover.1700502145.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=b2OIEP3B;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:1004:224b::b8 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

Make KMSAN use stack_depot_save instead of __stack_depot_save,
as it always passes true to __stack_depot_save as the last argument.

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v1->v2:
- This is a new patch.
---
 mm/kmsan/core.c | 7 +++----
 1 file changed, 3 insertions(+), 4 deletions(-)

diff --git a/mm/kmsan/core.c b/mm/kmsan/core.c
index c19f47af0424..cf2d70e9c9a5 100644
--- a/mm/kmsan/core.c
+++ b/mm/kmsan/core.c
@@ -76,7 +76,7 @@ depot_stack_handle_t kmsan_save_stack_with_flags(gfp_t flags,
 	/* Don't sleep. */
 	flags &= ~(__GFP_DIRECT_RECLAIM | __GFP_KSWAPD_RECLAIM);
 
-	handle = __stack_depot_save(entries, nr_entries, flags, true);
+	handle = stack_depot_save(entries, nr_entries, flags);
 	return stack_depot_set_extra_bits(handle, extra);
 }
 
@@ -185,11 +185,10 @@ depot_stack_handle_t kmsan_internal_chain_origin(depot_stack_handle_t id)
 	/*
 	 * @entries is a local var in non-instrumented code, so KMSAN does not
 	 * know it is initialized. Explicitly unpoison it to avoid false
-	 * positives when __stack_depot_save() passes it to instrumented code.
+	 * positives when stack_depot_save() passes it to instrumented code.
 	 */
 	kmsan_internal_unpoison_memory(entries, sizeof(entries), false);
-	handle = __stack_depot_save(entries, ARRAY_SIZE(entries), __GFP_HIGH,
-				    true);
+	handle = stack_depot_save(entries, ARRAY_SIZE(entries), __GFP_HIGH);
 	return stack_depot_set_extra_bits(handle, extra_bits);
 }
 
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/18092240699efdc6acd78b51e41ea782953e6c8d.1700502145.git.andreyknvl%40google.com.
