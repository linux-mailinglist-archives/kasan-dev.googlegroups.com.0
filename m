Return-Path: <kasan-dev+bncBDTMJ55N44FBBROYU3GQMGQEDIVGXDI@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id bYFCIEesqWn0CAEAu9opvQ
	(envelope-from <kasan-dev+bncBDTMJ55N44FBBROYU3GQMGQEDIVGXDI@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Thu, 05 Mar 2026 17:16:07 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 13A6D215437
	for <lists+kasan-dev@lfdr.de>; Thu, 05 Mar 2026 17:16:06 +0100 (CET)
Received: by mail-lf1-x13d.google.com with SMTP id 2adb3069b0e04-5a137c599ccsf28278e87.1
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Mar 2026 08:16:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1772727366; cv=pass;
        d=google.com; s=arc-20240605;
        b=K9ae5lI/5pPoq6uebvGH74E9ZRR9pKr4f4PrV/jVCHgOzSAGlsjawHzuSouJCfFPBc
         lgoEYi0IMnq/FCdsnjv25TtjgulqL651jCWIs2Fzdbjm1yxQwzXAHeQ/KB45qEanzSSw
         VQcbVFL0G6psTu+C0wsNwEMp3Y5ScenpWKzBeX1CdnYzd8ZEz+114XVvmdtKp5EjqqTv
         Ly5PHAx6ypXNBN/eOvae+vaHf9ETAeQFLZ2wmVMemz8Vu4UpfeaQLw08Yuo+gYeMdsO2
         bRbPqLqb32z9zAN2uEpvPgaqN1WUgVDJCyCKA7r/9KxGwOJisiPqany32q1WVm78s8hK
         Ep4A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=isdgWz138K+j+ItfA0Mrbwe3RQVRMcEg4r+sJsB8uYI=;
        fh=qiMlIYlWTecPS02t3O5j4XmxeAMu6mNCsZw87+0i5es=;
        b=DbzOGzc895pD/7XvOe3IUfQUG8FLGQvYYh6Wa4Z+IxsOmJrXuoeEJ2nSLvtyXTeZgB
         dNybEeJ6PRhVy5l2AU+y+//IS32T48eRpnMqMzLwzdR2/DES+JNIVG4UvKgz1xwsOIpZ
         x8Lm50te2uVnnuxmI4qeSTVgTJOAMmg9Bf3PDk6hhY7nVMGVSlDPUvyWdRJiSZdwzCmb
         2CIcDVwVG1Fp/UwSqOmSlBZX2Z27OjY26l/YSNha48KO+LXkEdWw0lF7LnflacYEo7v+
         TZopY2zZjmeg5uUVIw07BMi2NnCtrhz1CtX/UuQGUHh6YO+2wftx3Pk4mKawSzl2x/BV
         gObg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@debian.org header.s=smtpauto.stravinsky header.b=sVKDQJkZ;
       spf=none (google.com: leitao@debian.org does not designate permitted sender hosts) smtp.mailfrom=leitao@debian.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1772727366; x=1773332166; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=isdgWz138K+j+ItfA0Mrbwe3RQVRMcEg4r+sJsB8uYI=;
        b=UbCOX6/tMpeHrQEE0hpbgegV43qHBy1pCdSNNXqUQ0jEUNiiiibo/31tldizgzgKdZ
         V/pffJFS4U0cfnUqk6+v3iZ011IB/wrwQC2TBskPcoajq5ovbSHBOIaSETJCZuPON4SM
         rOxqhbqSvSyukvR7jC1MWm8LYx9qHTlNT/95+Yh0Oqa6gzauC1suSijzzN0G2jOW+v3Z
         KoVHzbcVrwbeWCtbXoy3q5AkZrZu8l86784Pegs/35Rl4aGCBSfFKn1n6kHxTaSCMMvA
         vYTHKGRVb1VAe3Dt4pOzTeC/cMm3bBUjTsaNo0VBzZp/xrhr2V/X+k+TwDww8DhANRzP
         BZBA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1772727366; x=1773332166;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=isdgWz138K+j+ItfA0Mrbwe3RQVRMcEg4r+sJsB8uYI=;
        b=RE8Gv2SidY5qOY0/l0c6q6saS18uiMvdRFPerZkJGGoeyA/UntSbiYjRzAkSLM2dW2
         EcLr9SERK/hvP9E1apVNUEgobkiBm3Phe2SY5kvTdfs08KDm38BSYWUocjPmVUk8ePGl
         vJOkCDY2WHW7ruJRXeBsQaWXT8a7Wlom88pj1MAdAz7gxx9haWDPuD8vpjxusLFMs4cC
         +YQXdNUj33WO+xkvQtn4d/crteGatH2iFZ6KGKlUUEz8GYECr0ojl+Dl8Lu0Na2lFfWZ
         S56CJrFh8tiGNRxPGm29ljmdKsl90w1H+5M/kFgPZ0ueNAknCZHtyOsTehXf3KOZowdZ
         Xk3Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVLDXM/i7IvAEEvxTUSSsjqEf0PoRI2hRRApC+sJwXcXWFfwhc/RMDne9CxOkfqfZeTTHuxLA==@lfdr.de
X-Gm-Message-State: AOJu0YyTyOY3Wr4vwgHbhfhJFN2Fgq/C0TGDXLg/koVzjj9j8Xs26FR1
	xIwASyJ2vKpEa8egS8PIq4v7SL5j9ssc9LRg4IEFj8p37JLp0PMZQB7y
X-Received: by 2002:a05:6512:1291:b0:5a1:2b2b:479d with SMTP id 2adb3069b0e04-5a12c2a37e4mr1146007e87.31.1772727365815;
        Thu, 05 Mar 2026 08:16:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HCq8agIQxLAcP/kQZjwATUapXInRcxBEnBeUVgRAC4kg=="
Received: by 2002:a05:6512:39c3:b0:59b:6ead:861e with SMTP id
 2adb3069b0e04-5a12fc4341els380543e87.1.-pod-prod-05-eu; Thu, 05 Mar 2026
 08:16:03 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVhdsN1EXSh+/GwSpQ8wLIwG/lCa5EBszXrx8b8ECVhC5swRgHeig4FrSgsr1x3HHpNYC335D6xRHc=@googlegroups.com
X-Received: by 2002:a2e:bc82:0:b0:389:ee95:e238 with SMTP id 38308e7fff4ca-38a2c572b8bmr36704431fa.1.1772727363278;
        Thu, 05 Mar 2026 08:16:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1772727363; cv=none;
        d=google.com; s=arc-20240605;
        b=LwPJNmtGFnK+Uy7OQoCyNloKG4yaUQ0UrQP7nxwvCnLQy7hBo1OnX33c9D2RTd3E9v
         IspZNJfJmEzkCGRxMQdoJWs99ZDYvvoQdEBp8+PbQC3el9CAL+rh7mL2l0UDjuKCFDuO
         bO4GZV3hbJ4goVm1wqtTIck2KOt8xqVPdLFokxGEgOuAF6igqVhDEggcdHA7Q1NQVzqW
         eBwKayRfPdSrXx4HuyG6+pOwCKwxn8/PzOaI9eXF1XO4+L8CFlzBUwdDKaB9uBpp1cN5
         9U34fWqX1gpBvtp5m2MfXAmMo/sMWIHCEdBtSIX1489G3CM1+5Ff1AgC8RkmMUMAi0MW
         Q8Gw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature;
        bh=/a+GWLIdcwkHBuwol8H36LzeFXVyS6jDGhiuvAeHeQU=;
        fh=ULATwvCSm9MH98k3lnaJHTf9T27YdHslpejL1iZxPpg=;
        b=bj62onG2IqqlozwHOO7erXo/wh1jAlx9NkMcNxDhFzHEy7CFKGkO63337Rww+Wc4/d
         13pptHPHtUVy/a7k96owcgMQ0KiHW69YztK/2ZMvNEv3AflGjsf6gA+MiE8dUcnuUMPu
         AmBKQKTdwg/rFvTehxLoE2I5JCN1PvaHSJthQfM4ejy9+JQLe3v9m5fI3HjnQdfcb9Ya
         +bZnCj1N2ryKffbT5RA3NmlzlaKD6DT7dqP6EXIx7doymXoLwGigY0482ub/tqcPkrVr
         29GLfly4BEzeat4PwwtYPctrZWb/xlduq41qlX1eLymc1MKWzcMqT1h4LgAhggSwG0dr
         1xTA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@debian.org header.s=smtpauto.stravinsky header.b=sVKDQJkZ;
       spf=none (google.com: leitao@debian.org does not designate permitted sender hosts) smtp.mailfrom=leitao@debian.org
Received: from stravinsky.debian.org (stravinsky.debian.org. [2001:41b8:202:deb::311:108])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-38a3aae1b63si124171fa.3.2026.03.05.08.16.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 05 Mar 2026 08:16:03 -0800 (PST)
Received-SPF: none (google.com: leitao@debian.org does not designate permitted sender hosts) client-ip=2001:41b8:202:deb::311:108;
Received: from authenticated user
	by stravinsky.debian.org with esmtpsa (TLS1.3:ECDHE_X25519__RSA_PSS_RSAE_SHA256__AES_256_GCM:256)
	(Exim 4.94.2)
	(envelope-from <leitao@debian.org>)
	id 1vyBMj-00Gqq8-Cs; Thu, 05 Mar 2026 16:15:57 +0000
From: Breno Leitao <leitao@debian.org>
Date: Thu, 05 Mar 2026 08:15:37 -0800
Subject: [PATCH v2 1/5] workqueue: Use POOL_BH instead of WQ_BH when
 checking pool flags
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20260305-wqstall_start-at-v2-1-b60863ee0899@debian.org>
References: <20260305-wqstall_start-at-v2-0-b60863ee0899@debian.org>
In-Reply-To: <20260305-wqstall_start-at-v2-0-b60863ee0899@debian.org>
To: Tejun Heo <tj@kernel.org>, Lai Jiangshan <jiangshanlai@gmail.com>, 
 Andrew Morton <akpm@linux-foundation.org>
Cc: linux-kernel@vger.kernel.org, Omar Sandoval <osandov@osandov.com>, 
 Song Liu <song@kernel.org>, Danielle Costantino <dcostantino@meta.com>, 
 kasan-dev@googlegroups.com, Petr Mladek <pmladek@suse.com>, 
 kernel-team@meta.com, Breno Leitao <leitao@debian.org>
X-Mailer: b4 0.15-dev-363b9
X-Developer-Signature: v=1; a=openpgp-sha256; l=1075; i=leitao@debian.org;
 h=from:subject:message-id; bh=ayZa6eUX42z6X1IZOjyqGaQSXE2kotFlsEPGUri5Ogw=;
 b=owEBbQKS/ZANAwAIATWjk5/8eHdtAcsmYgBpqawzFjrISbfyzAjsU4t6y0T8xqK9Hf+IB0mlb
 0pNMWyyX1+JAjMEAAEIAB0WIQSshTmm6PRnAspKQ5s1o5Of/Hh3bQUCaamsMwAKCRA1o5Of/Hh3
 bTAiD/4nJSvjlW9FdyS7S6CjWzJrDIyYotlGnLrT3S3LmxR6XhIdnb/3pTSR+x8DxabOBXpTArH
 FCvfGlvqv//IQ/tn1GV1mPZyrmS8h09o6R6zmAS9NsDzL3zbP6K9y3TBRVjp/nilf/wDl9lI0TQ
 V8c7LOR9KNyLGWUCVcBmW+1rwFC3Xl9NK7vOoGOZ6gy7ANMa+pfoEPkplv9uM4GUtBvuG+6V4fI
 4C6ZN76r3W6+RhIkdjbkonACIPn/YwkuYBH0jcLRrH9k/q7953uXuhgA8xZs5anoOX+h4hsJw56
 PohrSrUlhxgi5JS5R7Bmx6D0Lvm+tZE5hhUjyIe3ZgR3ugYdo1jKkxumvb58VussbosFSIEPT3v
 PTTMp9Ty5p59OzhCMM6BUycK8+lbHCEQrip7yMaQUWMforoM1lsvNPY6jvwN5N38xqzo6+Z13ue
 QOxlRIcJUDjsEqPQdDV8HMvtabJ4YSHeU7DtRLfMurGx7IlJEQB9Cypn2c8zTSgeKmGYhjJ4lZm
 lqnRe6AcvsHdpUc3/9W0CXWY7JUhbzt4N6WsjVp6fBSv6JcFi9RHyFRNDy3dRMOnuSeCLN6/olm
 35FDuSAAo4Z+PGcNVnfdqdS/GL8ag/jW22mTYsYDTLR9wIPTIIkT4kFYKwNOdEatKCBW3ZqC0N0
 SEjfcE1f9BcyL0Q==
X-Developer-Key: i=leitao@debian.org; a=openpgp;
 fpr=AC8539A6E8F46702CA4A439B35A3939FFC78776D
X-Debian-User: leitao
X-Original-Sender: leitao@debian.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@debian.org header.s=smtpauto.stravinsky header.b=sVKDQJkZ;
       spf=none (google.com: leitao@debian.org does not designate permitted
 sender hosts) smtp.mailfrom=leitao@debian.org
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
X-Rspamd-Queue-Id: 13A6D215437
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-1.71 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	MAILLIST(-0.20)[googlegroups];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	FROM_HAS_DN(0.00)[];
	RCVD_COUNT_THREE(0.00)[4];
	FREEMAIL_TO(0.00)[kernel.org,gmail.com,linux-foundation.org];
	RCVD_TLS_LAST(0.00)[];
	DMARC_NA(0.00)[debian.org];
	MIME_TRACE(0.00)[0:+];
	FORGED_SENDER_MAILLIST(0.00)[];
	TAGGED_FROM(0.00)[bncBDTMJ55N44FBBROYU3GQMGQEDIVGXDI];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	NEURAL_HAM(-0.00)[-0.999];
	FROM_NEQ_ENVFROM(0.00)[leitao@debian.org,kasan-dev@googlegroups.com];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	MID_RHS_MATCH_FROM(0.00)[];
	TAGGED_RCPT(0.00)[kasan-dev];
	RCPT_COUNT_SEVEN(0.00)[11];
	TO_DN_SOME(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:dkim,googlegroups.com:email]
X-Rspamd-Action: no action

pr_cont_worker_id() checks pool->flags against WQ_BH, which is a
workqueue-level flag (defined in workqueue.h). Pool flags use a
separate namespace with POOL_* constants (defined in workqueue.c).
The correct constant is POOL_BH. Both WQ_BH and POOL_BH are defined
as (1 << 0) so this has no behavioral impact, but it is semantically
wrong and inconsistent with every other pool-level BH check in the
file.

Fixes: 4cb1ef64609f ("workqueue: Implement BH workqueues to eventually replace tasklets")
Signed-off-by: Breno Leitao <leitao@debian.org>
---
 kernel/workqueue.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/kernel/workqueue.c b/kernel/workqueue.c
index aeaec79bc09c4..1e5b6cb0fbda6 100644
--- a/kernel/workqueue.c
+++ b/kernel/workqueue.c
@@ -6274,7 +6274,7 @@ static void pr_cont_worker_id(struct worker *worker)
 {
 	struct worker_pool *pool = worker->pool;
 
-	if (pool->flags & WQ_BH)
+	if (pool->flags & POOL_BH)
 		pr_cont("bh%s",
 			pool->attrs->nice == HIGHPRI_NICE_LEVEL ? "-hi" : "");
 	else

-- 
2.47.3

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260305-wqstall_start-at-v2-1-b60863ee0899%40debian.org.
