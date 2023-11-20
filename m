Return-Path: <kasan-dev+bncBDXYDPH3S4OBBQ6N52VAMGQEGGY4CLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 783CF7F1C7A
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 19:34:44 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id 2adb3069b0e04-50798a25ebasf2982204e87.0
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 10:34:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700505284; cv=pass;
        d=google.com; s=arc-20160816;
        b=XmOO9GxtfKhePHnYBBbj2d/Iudf10idq8G7impiUp6MR+N4jUdr8cFmhkTIKE/G69I
         q9VUGCx7Un8B1d2c/nX5C2SlE49Q21omTNglODCCwhxHm65/EEWb17p9nrlRWiHzE0N7
         oSV3KCU0k4flXFtlJBjAqYYzIPWaUeYvchO8lVwksS9GlMUOcMPIGh5Zt39sLSKGC7nj
         wYZqtQuFv5ndvXsUZwYoqPTax2LAeVmYXBPLhlMZ3UlNoAFWipZYtJtIled4FAkG2Ls9
         Lpolw6g903vdFZ/LqcOh5jeyVoxhJ4jVEcLfTyR13QrIMdeVie2/NkZEYa7mN3MPZB66
         hVLg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=/K5Edq66IntAGgV5NSi4+GqssxBp3BErnpUwXevEr+w=;
        fh=dfD2X5Mb6QAP79KDvnu8aL/16Lml7JbeXAz+yHwdS1Q=;
        b=YirTFkitauWxsy5y/rfxi7lDGHvejNkneD7PbWowHvHDG0KyRb2nPzhcPVrrFvmuly
         dR+Zn0YXllDC6/wfwSIx/SREf9MWKEJV2gSHmC4CFH4Xh7ylAABOf1M67GBLO/+xo4AB
         FY+OCJlhirP9MlZkBXaMH1JXsULW4REEfGq1fp6Mb8qScd+x8iINpSaPy5WAR6gknlZu
         npdBV+MctjUZuHSXg0JFr/7emlzJ08RqR/AwPfxFK+sWW5rA7hz82l7IfuWIYGtWu6ji
         CTKfnjyaJlIAT+hAdbUw1e8Yvfnzs+OLDaa7Yfql7sI4pD8PM5rBPPXPz4TZ0wsJwFeE
         1J6w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=iabcfhh4;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700505284; x=1701110084; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=/K5Edq66IntAGgV5NSi4+GqssxBp3BErnpUwXevEr+w=;
        b=NW007oginCGFuT1hACl65UDuKVkrvim0P9DqdL64f3me8V8CgcfbVadxOlSFmQ/nJT
         YN9mAKDxf5rjLRHtScsKeZtlt4gOj6il3jGBceaaig3iQhMTpntD7t6aRQji24YA/U+3
         2d+rsGD+wbpYnrDYv8C+NPp4miq1uKPGxB00YXrP4D/4aSYOCYGUGKgYyE54Sm6sH+wo
         bKs70PSEWI3N6Hdd5f+jV1/MVcqmxkYuBXxYtRKvLjggpCkEhRBCvp8cSKodW0j4a98N
         /kHJQUHXna56D3f1N8ccWyn8V+4VEOB/XJsHsGvlN7GAWUFOM5orVbzFuDffYgl2U86G
         +/8Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700505284; x=1701110084;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=/K5Edq66IntAGgV5NSi4+GqssxBp3BErnpUwXevEr+w=;
        b=w7NheLCtWcVzZ9aWWc71AJJsJFK7TV43ujZMxEr+NgI7ZGzIgRGGXQMyq25vI/btv2
         yNsQJryotcCpPof9534DgUlpLDVQpynXmMrPSjbyqyYHpZxpAV/FyXLtabzCLaA0JEoo
         nbo1ukeBbf9r68TjrT7z9fVd1yM64jLv+jYkd2Fc9DJvyu382kIK7oN9Mvr+Aijmogkd
         gLTPTC08CslCLSt7U/w/4nzY00t3eEDPEUD2OORg8+HlA2Q94KzbE2U8N1BlGrZkMfZ1
         PYvWk3RVuj4tMCgnQZOysdSICvXJmWr5ZC5VjokxFMoOIfLP5ixeCGdkjmID1zYG3CE0
         +GrA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwMu2QmMTSG4rMCloEwec52S+NVdxJZ29NE3fbZahwQt4ccOCV+
	RyJERSs9CsaSTznUeRSI2NY=
X-Google-Smtp-Source: AGHT+IHJcaioENhSXl+Y1Qx0uxAEbHtYTHLpDpf5C/+32GGFSZTom8HNHyw9lsOwAJ7ureT07F+MPQ==
X-Received: by 2002:a05:6512:3191:b0:504:7d7e:78dd with SMTP id i17-20020a056512319100b005047d7e78ddmr130711lfe.23.1700505283381;
        Mon, 20 Nov 2023 10:34:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:522f:0:b0:50a:a6cf:a355 with SMTP id i15-20020ac2522f000000b0050aa6cfa355ls639944lfl.0.-pod-prod-00-eu;
 Mon, 20 Nov 2023 10:34:41 -0800 (PST)
X-Received: by 2002:a05:6512:15a2:b0:50a:a327:4ade with SMTP id bp34-20020a05651215a200b0050aa3274ademr103400lfb.8.1700505281387;
        Mon, 20 Nov 2023 10:34:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700505281; cv=none;
        d=google.com; s=arc-20160816;
        b=qm3Wu6hpvYojr46Ee1OQoeTDvJwDfHTc8apCTeP3PQr3dW+d2Co/eGyBQDHx+RqIc2
         5p3yJUbgrJsLPoBI/VqMgk4qK4nlUhjcbsuMILh7zA+LAoS5u0SjmNSdlKVljXrU4+Qb
         vg4tC3mwGfRD1UlqfYbh+AVkIB7vXkdofkLZGsn/k/l/ORARtchMR63xRdQiAiFM44Zc
         Wdc5LWLpPrnkS7AZ59Z9QG5V0dO1+rCNT3Onbgee74SfdYBckqb7tOuMufbLx/mGxgu4
         G1PuX5+Y0+rfv2omjxLjpBuHVf2NfmvJJN8s2SXXiWJGockZnRK+wSojJjr2JU5FR0zH
         A80g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature:dkim-signature;
        bh=Dcjx3iROX6mBTSjg5k3H+GZh2kSdjDYPdKkv3u7xaxo=;
        fh=dfD2X5Mb6QAP79KDvnu8aL/16Lml7JbeXAz+yHwdS1Q=;
        b=fMPpUBKQsPcWPuZuJtj1q0/MaqXUk5u6/a6b4+qaZeNJ2Cptrq+3FHqu6Wyf4UtC5i
         x7eAp1TBkpw2rEJz+aWI4CJK7a6X6sRkQ0IcnZEpoPe5/Mal+Zdsk3c8e6afC5FHTvta
         5rJ7fxfmbbdGp0vVsFSMBSs/DBJBd/hCh5gchGV69TmE5mJP8v25KFSilWTuj7/3jvSN
         pmSuv5r6H7Kp4R93bOz/1wQFM0ng0iRizTaeLwRHAkwpbrY8b2f85UaoBSAtxQ9JdnVa
         71JoMxpRvakZwM4BMj85AZUW4uezlBtUjvDCUBPsrpLEAzUkgY+7VGGj1Jw7K8VRYDMi
         1+Ww==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=iabcfhh4;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2001:67c:2178:6::1d])
        by gmr-mx.google.com with ESMTPS id fb13-20020a056512124d00b0050a72e696casi328926lfb.6.2023.11.20.10.34.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 20 Nov 2023 10:34:41 -0800 (PST)
Received-SPF: softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) client-ip=2001:67c:2178:6::1d;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id B1C1A1F8A3;
	Mon, 20 Nov 2023 18:34:40 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 77EF713499;
	Mon, 20 Nov 2023 18:34:40 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id oCHMHMCmW2UUMgAAMHmgww
	(envelope-from <vbabka@suse.cz>); Mon, 20 Nov 2023 18:34:40 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Mon, 20 Nov 2023 19:34:16 +0100
Subject: [PATCH v2 05/21] mm/memcontrol: remove CONFIG_SLAB #ifdef guards
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20231120-slab-remove-slab-v2-5-9c9c70177183@suse.cz>
References: <20231120-slab-remove-slab-v2-0-9c9c70177183@suse.cz>
In-Reply-To: <20231120-slab-remove-slab-v2-0-9c9c70177183@suse.cz>
To: David Rientjes <rientjes@google.com>, Christoph Lameter <cl@linux.com>, 
 Pekka Enberg <penberg@kernel.org>, Joonsoo Kim <iamjoonsoo.kim@lge.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, 
 Hyeonggon Yoo <42.hyeyoo@gmail.com>, 
 Roman Gushchin <roman.gushchin@linux.dev>, 
 Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
 Alexander Potapenko <glider@google.com>, 
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
 Vincenzo Frascino <vincenzo.frascino@arm.com>, 
 Marco Elver <elver@google.com>, Johannes Weiner <hannes@cmpxchg.org>, 
 Michal Hocko <mhocko@kernel.org>, Shakeel Butt <shakeelb@google.com>, 
 Muchun Song <muchun.song@linux.dev>, Kees Cook <keescook@chromium.org>, 
 linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
 kasan-dev@googlegroups.com, cgroups@vger.kernel.org, 
 linux-hardening@vger.kernel.org, Michal Hocko <mhocko@suse.com>, 
 Vlastimil Babka <vbabka@suse.cz>
X-Mailer: b4 0.12.4
X-Spam-Level: 
X-Spam-Score: -3.80
X-Spamd-Result: default: False [-3.80 / 50.00];
	 ARC_NA(0.00)[];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 RCVD_TLS_ALL(0.00)[];
	 FROM_HAS_DN(0.00)[];
	 TO_DN_SOME(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 TO_MATCH_ENVRCPT_ALL(0.00)[];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 REPLY(-4.00)[];
	 MID_RHS_MATCH_FROM(0.00)[];
	 NEURAL_HAM_LONG(-1.00)[-1.000];
	 R_RATELIMIT(0.00)[to_ip_from(RL563rtnmcmc9sawm86hmgtctc)];
	 DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 NEURAL_HAM_SHORT(-0.20)[-1.000];
	 BAYES_HAM(-0.00)[42.60%];
	 RCPT_COUNT_TWELVE(0.00)[25];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 FREEMAIL_CC(0.00)[linux-foundation.org,gmail.com,linux.dev,google.com,arm.com,cmpxchg.org,kernel.org,chromium.org,kvack.org,vger.kernel.org,googlegroups.com,suse.com,suse.cz];
	 RCVD_COUNT_TWO(0.00)[2];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=iabcfhh4;       dkim=neutral
 (no key) header.i=@suse.cz;       spf=softfail (google.com: domain of
 transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as
 permitted sender) smtp.mailfrom=vbabka@suse.cz
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

With SLAB removed, these are never true anymore so we can clean up.

Reviewed-by: Kees Cook <keescook@chromium.org>
Acked-by: Michal Hocko <mhocko@suse.com>
Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/memcontrol.c | 5 ++---
 1 file changed, 2 insertions(+), 3 deletions(-)

diff --git a/mm/memcontrol.c b/mm/memcontrol.c
index 774bd6e21e27..947fb50eba31 100644
--- a/mm/memcontrol.c
+++ b/mm/memcontrol.c
@@ -5149,7 +5149,7 @@ static ssize_t memcg_write_event_control(struct kernfs_open_file *of,
 	return ret;
 }
 
-#if defined(CONFIG_MEMCG_KMEM) && (defined(CONFIG_SLAB) || defined(CONFIG_SLUB_DEBUG))
+#if defined(CONFIG_MEMCG_KMEM) && defined(CONFIG_SLUB_DEBUG)
 static int mem_cgroup_slab_show(struct seq_file *m, void *p)
 {
 	/*
@@ -5258,8 +5258,7 @@ static struct cftype mem_cgroup_legacy_files[] = {
 		.write = mem_cgroup_reset,
 		.read_u64 = mem_cgroup_read_u64,
 	},
-#if defined(CONFIG_MEMCG_KMEM) && \
-	(defined(CONFIG_SLAB) || defined(CONFIG_SLUB_DEBUG))
+#if defined(CONFIG_MEMCG_KMEM) && defined(CONFIG_SLUB_DEBUG)
 	{
 		.name = "kmem.slabinfo",
 		.seq_show = mem_cgroup_slab_show,

-- 
2.42.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231120-slab-remove-slab-v2-5-9c9c70177183%40suse.cz.
