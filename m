Return-Path: <kasan-dev+bncBDSN5PVHZYERBD4L67AQMGQEWX7QZ3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id 2315CACB84E
	for <lists+kasan-dev@lfdr.de>; Mon,  2 Jun 2025 17:39:17 +0200 (CEST)
Received: by mail-qv1-xf38.google.com with SMTP id 6a1803df08f44-6fac4b26c69sf46068636d6.3
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Jun 2025 08:39:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1748878736; cv=pass;
        d=google.com; s=arc-20240605;
        b=ai86dWBh2vgYtlN2+86SAqYV/Haryhd/Mk3xlYwNhYPS3pXIM08fLivA9U1xOAjuyN
         QUdIXxn9O9uNzjJT88Wu/98A7axzaBQ6CAbg63eSTniRARn+cv3ePPQnkoQfeKPHGuQ4
         oAtLOa7UpMvmE2rZ+wQpjGLG+iKG6TGkUu6yAZKiaIFyb3hPDcFpXqgv3iy/mChccr1R
         eysn9McIBrqJBXmC+SsT2Vl5mEiAV+qrB9y0QiVFFtMb9Zqg8fYuYF1sWJh/ymZHafGi
         6W/tndIzKqTs2Kx722V0d2b3cPwMKFDWDtS2i/oQ0bedMuhrkAeBEvlQiA6ZD2epgblv
         KlCg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature:dkim-signature;
        bh=WaxfmFOIMPxphlpIgolegApid29LebTGcxrLJ84zonc=;
        fh=rHkqhmLGavuLIvybKgUtpl4bTlAa5r8fESfqk+UzBRc=;
        b=NEChLbtcOIlNT/tvRXWo2h/iZUfmM89OJnO5ePANzLiHyWceebXfx0PCrLn6kDsm/W
         RYFZfyR7Qg2uFg1MI6w1eTZTarAOWHm5STj02CfR+SV6F8wQgCpqQEVmabMa8OirFbel
         fuy1lhik05HCpR3HxfekFZk6JJr6Mtvjwwc9/dpNcl4CF44oIX/i1SE/e5A4HOM09ckK
         ggnIv9w7swCQmImJN/fnHQi/MSuq+H0gD0D/xEqQioiasB5Od4XySFCGATnO/53f+9xP
         UrG86Iy5HMzhpPPQgYed2D/Qu7V5/XD4NnmrbyY6qeMg5TSYw44lxG6F9yQSmJRWQgUM
         xuqA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=GM3DDa5F;
       spf=pass (google.com: domain of paradoxskin233@gmail.com designates 2607:f8b0:4864:20::1034 as permitted sender) smtp.mailfrom=paradoxskin233@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1748878736; x=1749483536; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=WaxfmFOIMPxphlpIgolegApid29LebTGcxrLJ84zonc=;
        b=Afo+DWvNL7vq1NNIMbg7xP6sUgDEfFIMqzqFC+Zq9SpG4x7ywluccODFEwf20F5Jls
         4wpYVA4VsrMp8U0q3RKfY92grAq/u7fJcYPabrfdtLDKv9ImZn3p+Ncj3kSYLksJOg4F
         2gUvEer0BDne/jyd5oyzj+xoowV4c46nON3lMmPiRK862ae8Pjy/kPEJffQve1b/zLQo
         W9gVFgW5Caft2+dqngMI4OCVbxcrq7Dv4ZCcGUdOU4NztfYLWhyuZqJOiq+DzJfu1ty4
         QQHHk9jNNxp32ByA8En2mxUCN34/Tyiwc5f5wbY1r/hiea/OF3AMsFccAPJNyPtKjFDA
         1GJw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1748878736; x=1749483536; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :from:to:cc:subject:date:message-id:reply-to;
        bh=WaxfmFOIMPxphlpIgolegApid29LebTGcxrLJ84zonc=;
        b=LirZPr9OFAlVcvYwX3ZO9O1mgnt08fvhWwvtXRsfsmKOPceFn9uaeb780fjF4m8E8w
         /BA12+pyslju3f48DDA1vqBINtprJAmQtDmqb4FQrhdWPVrSfw+Z5pFtwIMAEA8NExDX
         rP+BSBCyTcYbesJ8sKwX06prViaSkrXpU3mG/n4cKqGwbZ1s0qjaQl2kZR/J3XTqehDo
         3nStvsn1BdVwvFFClGrzvfqZWgJnzucWFQV0kHTpYkIVsyqgHck4FWieOJsDK68rF+tB
         lcIXK8TrU3x4BtKWYfwYKG4u1GjgoojDTxDQ+BZA6jdU0zFr6HP78apa+seQ5Rj7MDE8
         4qFw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1748878736; x=1749483536;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=WaxfmFOIMPxphlpIgolegApid29LebTGcxrLJ84zonc=;
        b=e/S0coIlSfzQwdeXae2qqic3OabiN9wDTqjOrW6FQdG/eWcMVS0YFXWkPQgE1whzbc
         UfijnVhJz8iMLPgxWjQbpmeAdLazZOTnYMsiW6rc3RZMgIroYlOm62dC+YojFTrNK9gZ
         TXs20FLsHG8y3H8/pvyT4m8hu+zzMEaAIqba5JyjnJzrmPZZu9mVKZrzY6om1SldzvRx
         KA6RC1Z+JPeiQ3cwjRVvtHl8AaMZZasolKKwF4/J8w+RZ3kMqEl09UglnfSNtU2RYqCq
         F45X/F7ZHyaMwOJnTT3b86DHYbo7kKx/yAK4eJh6wfXG3scTkFMWuf/Ixy995VfssZ3U
         UI1g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWTYskJKlpjPHSsjXRdpSpvXSbEoxw99VFGXfdm6ZqNXPtceR0jCK8TDg2IiLrCLuA7G5DkrQ==@lfdr.de
X-Gm-Message-State: AOJu0YxyYS1uZ4prXpl4g7/quzbS8xhjTHvEi90qi/JkwNGyFl79Wnaw
	fH0M71XTpgHccLcJ1koQHrafcJYVAYqZCnXBYW7SX7geLXLZiU831wQb
X-Google-Smtp-Source: AGHT+IFPNMOKPw8H7uExPF25c21dYmdqXG6bwB28kIqjIUx153sYiebQU5GbKp0cXf9KJOHn/rYsuw==
X-Received: by 2002:a05:6214:29ed:b0:6f4:cfb3:9de1 with SMTP id 6a1803df08f44-6fad916409emr135070746d6.40.1748878735971;
        Mon, 02 Jun 2025 08:38:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZc5SN6MPq3B1Dt1K7Bg6PFAWFm/LVtm03EpYI0HRCoDEQ==
Received: by 2002:a0c:aa56:0:b0:6f8:afe1:86df with SMTP id 6a1803df08f44-6fac5d2985dls77148956d6.0.-pod-prod-08-us;
 Mon, 02 Jun 2025 08:38:55 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXpL/7kNLYKYblXtrW9wm9kjCsBeIHamc6KVztzuxABRo8+sig3aDsL9P2gS0Uf/PwRYCHhMc+qDlU=@googlegroups.com
X-Received: by 2002:a05:6122:2194:b0:530:7e05:3839 with SMTP id 71dfb90a1353d-530938008aemr5951256e0c.11.1748878735112;
        Mon, 02 Jun 2025 08:38:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1748878735; cv=none;
        d=google.com; s=arc-20240605;
        b=A5vZu8LQlSoOjfXYT00gC5XgI+HenJwxkQJY9b4RhpmofOIPsf2pBtry19+C14ZVCs
         ywawb4Tlo7NYUtZVbjV4GCCR4Y7nHNPFkqE65xhfKSYlDAjSG3i7IbKh83H6t2FdFGp2
         QlWd1uFKW8On8n3P9rZPH/hVsSWHWVNOy6CZYlYSpax+Juwb8drTuWZFpeMwfQ8CcVUs
         uBesdNScAsyY3VwZKDGszAqBFH9C0Ax2PN4vHjQh4uuiebCve7/Up658TNJArgPzssdx
         I4Ct+JiBPY0FMFsygnp9ACzy0Y6qepkvOltQFWAGcB+MbFOHYJaYx6ODuqqsGkWQkJL3
         TqcA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=K7WwE2szzySMaSbvnDjlIKqzFYgvBzLvgLKYcMgSkS4=;
        fh=sAdDxJpUuVKwWCg7l2AQeBEkNXl4rnV1aQszZUG6+T4=;
        b=Cmoa++ppS+UEbjnC9Uv6OYrmy95A0dcUs/4g1X09MzNMEN4tuNQYzz7e7gbREdHHDq
         mnsmhdghNO3tyKXqoMrYjZ/lEg1E3ECInnQbIZX+fpSV/HpKM6MNu9XMyQWqwoUUPtiS
         qdVChxKCEK9ZmbCAUi8nlDnf5l2SfQ/dKzQeauIehhYyXZFSq8fptjHWV3d45LxpEYWt
         EZJqnGflZOoLMSITwyIUon2qdAYxlxAP6ho8pKtEQLPzn3bYTSJ2X9pxixZ+GYy3/QY7
         p+nHjcqyBJl7wkx1DS93/gIrTvBfE8AjL/44UBIDTwJ/reHl942H7MbFGrWio0Yr6s72
         za8w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=GM3DDa5F;
       spf=pass (google.com: domain of paradoxskin233@gmail.com designates 2607:f8b0:4864:20::1034 as permitted sender) smtp.mailfrom=paradoxskin233@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x1034.google.com (mail-pj1-x1034.google.com. [2607:f8b0:4864:20::1034])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-5307482e9e1si457401e0c.0.2025.06.02.08.38.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 02 Jun 2025 08:38:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of paradoxskin233@gmail.com designates 2607:f8b0:4864:20::1034 as permitted sender) client-ip=2607:f8b0:4864:20::1034;
Received: by mail-pj1-x1034.google.com with SMTP id 98e67ed59e1d1-30e8feb1886so4893559a91.0
        for <kasan-dev@googlegroups.com>; Mon, 02 Jun 2025 08:38:55 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUeap3I1ObI4YRTqia/FOLzYSpMfN2dBlEW/n8QFdB45vjO/ZFgTuQy03Wtax+MgjhbuRvFdAslMDY=@googlegroups.com
X-Gm-Gg: ASbGnct2c86XUmSxLdZ55627ROhblkrvUI78GtzWgkL27lLSG0tDwKMNo+db64t7zHm
	0i0zdCnNR7nbeNhjQKzkF+fyud7uOleaT1aJ/w7nCPHrUrRSHW3vl7lIFj/wV7vWFYvTTosckJ1
	H6IcdgzkTihfcNAkObpWN6MS5EHYqWp/21lXX0OB/2s3fkf/jTJFp4VZxUWpHOL+nKtkUlTP2UO
	jxzjx/eADL9nVtqyyuG1mU+xYTIV9nyqK3lb3is92vUJLUH87Ktf3zNEfuOa8B5AJ1iEBuJLNo8
	nOq+4FimZkIKGKKNJ/VwhcN4lt6f0U60/kNausmCc0gIe8ao9F22WZWCwrB+lz/tvsZGIWFJAaL
	4NfxPPqOH9Q5aMA2OHTao3t0JcvgFR4FGWbfyjPOXulwOK4SnuHU=
X-Received: by 2002:a17:90b:268a:b0:312:db8:dbd1 with SMTP id 98e67ed59e1d1-3127c6bcd95mr12754409a91.5.1748878734517;
        Mon, 02 Jun 2025 08:38:54 -0700 (PDT)
Received: from va11o.lan (n058152119137.netvigator.com. [58.152.119.137])
        by smtp.gmail.com with ESMTPSA id 41be03b00d2f7-b2eceb9d1eesm4980157a12.54.2025.06.02.08.38.50
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 02 Jun 2025 08:38:54 -0700 (PDT)
From: Junhui Pei <paradoxskin233@gmail.com>
To: kees@kernel.org
Cc: elver@google.com,
	andreyknvl@gmail.com,
	ryabinin.a.a@gmail.com,
	akpm@linux-foundation.org,
	kasan-dev@googlegroups.com,
	linux-hardening@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	Junhui Pei <paradoxskin233@gmail.com>
Subject: [PATCH] ubsan: Fix incorrect hand-side used in handle
Date: Mon,  2 Jun 2025 23:38:41 +0800
Message-ID: <20250602153841.62935-1-paradoxskin233@gmail.com>
X-Mailer: git-send-email 2.49.0
MIME-Version: 1.0
X-Original-Sender: paradoxskin233@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=GM3DDa5F;       spf=pass
 (google.com: domain of paradoxskin233@gmail.com designates
 2607:f8b0:4864:20::1034 as permitted sender) smtp.mailfrom=paradoxskin233@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

__ubsan_handle_divrem_overflow() incorrectly uses the RHS to report.
It always reports the same log: division of -1 by -1. But it should
report division of LHS by -1.

Signed-off-by: Junhui Pei <paradoxskin233@gmail.com>
---
 lib/ubsan.c | 6 +++---
 1 file changed, 3 insertions(+), 3 deletions(-)

diff --git a/lib/ubsan.c b/lib/ubsan.c
index a6ca235dd714..456e3dd8f4ea 100644
--- a/lib/ubsan.c
+++ b/lib/ubsan.c
@@ -333,18 +333,18 @@ EXPORT_SYMBOL(__ubsan_handle_implicit_conversion);
 void __ubsan_handle_divrem_overflow(void *_data, void *lhs, void *rhs)
 {
 	struct overflow_data *data = _data;
-	char rhs_val_str[VALUE_LENGTH];
+	char lhs_val_str[VALUE_LENGTH];
 
 	if (suppress_report(&data->location))
 		return;
 
 	ubsan_prologue(&data->location, "division-overflow");
 
-	val_to_string(rhs_val_str, sizeof(rhs_val_str), data->type, rhs);
+	val_to_string(lhs_val_str, sizeof(lhs_val_str), data->type, lhs);
 
 	if (type_is_signed(data->type) && get_signed_val(data->type, rhs) == -1)
 		pr_err("division of %s by -1 cannot be represented in type %s\n",
-			rhs_val_str, data->type->type_name);
+			lhs_val_str, data->type->type_name);
 	else
 		pr_err("division by zero\n");
 
-- 
2.49.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250602153841.62935-1-paradoxskin233%40gmail.com.
