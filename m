Return-Path: <kasan-dev+bncBCXKTJ63SAARB45DUGZQMGQE5WMUT7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id 8AE86903D6A
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Jun 2024 15:32:37 +0200 (CEST)
Received: by mail-pj1-x103d.google.com with SMTP id 98e67ed59e1d1-2c2dd94c728sf3113080a91.2
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Jun 2024 06:32:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718112756; cv=pass;
        d=google.com; s=arc-20160816;
        b=BYAEymvBGphlOsqtfyo/297W1pjunzVr5ip7itU7rpZi85nihVdnL1H5OfriqfBoxf
         wx9PFY7TDFNZ7ZRfisw6lkIjWU1+oKio6y8NHt0ERdJCEv6k3pKJx0j6jkGBzXqH0zSi
         hFolL69Px18DqvEoA+SjzD51NYl5nir0BEWsWiid3D8Vk4nvNxvs64ugxYmFzgWFRE1L
         PsXAvR+bCNrRGcw/SPm30x4dD5xDPmvFRbjeofx5DOpvQAMuk4v5a0aGx0ZiXX+OHrGh
         DtGbw3enH4WJ1Vd0ohrdxV0jZ9Daul2ajCATchwD8QuEGoA/VT3z9nGy5DNUzKrOafod
         +sOA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=lox67gpjQEskdkWhaHc8I40YoFoBXI9vNhYZnaBehKw=;
        fh=kjFRw+972K8QbytycYOERMJA8ir1eBB7fqqpt0g5pqA=;
        b=O9e3OpQvYGpP2zMAI3+WCZfLSN9Eomnaw3dLbmKsl6bvPl2W4ODa8A7jZPwR9I0vF5
         dK2UKolP3khhLIHj51E1bU8x3scXH59WhwZd56KYSNvBcZhbkqeyu6vdweP+Vbcf+Kbv
         RUxN4hC3H8yedV15h2pwVCRZOFhW4Vf48W2dwQDxFBExHaq3Y+z4ONwM/cOaIc+jYEWf
         F+2g/jxS3KOcFltqGl1l6w1EkCXM9NER0Va4ZvmAsEiyCvuuWq3VM6S/ZcFxoALPRU9R
         A2xCayGlmaGzpCaNWEkI+Iie9Iqh0RGUu+1Lnrx0pcnw4sjrg3l3fHG72/ghPiO4JnlW
         9zHA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=cP2SbfcS;
       spf=pass (google.com: domain of 38vfozgykcxabcuwyvuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--nogikh.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=38VFoZgYKCXAbcUWYVUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--nogikh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718112756; x=1718717556; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=lox67gpjQEskdkWhaHc8I40YoFoBXI9vNhYZnaBehKw=;
        b=SMoIf1FWuucgDYBtnLod60qqiwLFfsFs92HaI/ESZNrtn6wlBmQGiHc0bu7/pW1U6k
         XD4s0FXtrt+r8TAGehg+viHuFrBTyKoJXlNB4oi14B1uB8rm6ubteEzAlaiHkNlGyx04
         ws6LZi0IoNwFEPFv9iVCAVw+yfZ0DujqQ/uujkt8EyL4sM7+s/SiFu4VoDLOQu0tFBcp
         nZHLccTEbZCcWwzmlCD76A4OgXtcW0qLbMSpS/RFUZwd2f5dwlxL4cUFjIzL5HMBOmKB
         Q9slSE7Kg41yit44UPlgRWAWErykp0hRv9L9YYJpGnxxzLEcNN4ZNpxNzChT2jM3SgAu
         t3tg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718112756; x=1718717556;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=lox67gpjQEskdkWhaHc8I40YoFoBXI9vNhYZnaBehKw=;
        b=TD90/+Kj2q77iYXU7MYCmnyzRvut5aRwBk/yxR0BkwGZk1Kf/bD2WjrjS7BQ8LpYue
         /fIXut0aCFRPsiMVeiuX5oRcAtP8TeKpm6U89K+JYdK1kKe/UFa6BvrD2TJjtuRr3tBZ
         JYNGREf/5CuWlBcejR3qE8llg+rWCOP2mIWk03QXEDg955PBY5h///4l0BK/CFSyH+8M
         mzW7yQIXUv4mPZK6NRtzHv+QwZ4t3SiXROcojPEzSInh8QSZ8P+Zq+8dL4YFFSVVWNjZ
         axDTjWQH7GqGXBe6dZJ2iJnnNDGbraX8KMhiR4P0w9JQubYluDmB6unW2Z27PrusjWWh
         euVw==
X-Forwarded-Encrypted: i=2; AJvYcCUN2xGTQDEiN3k+nEl6OC0kYkIMTByKJa0WHJp9kF3IPyEDRXQ7r2MLluMO1ZpcJjfNhKjcU5+MlDa+5q6IhclOuIEYQin/hg==
X-Gm-Message-State: AOJu0YwguwpGhareDb424ThIebshSSLteTNWwBNGbT40UrbSsxg8+c15
	wgjKV5FyRjypZL3Vqzph+/s43Oq1KNfMmVBO1bxFuFb7UV066VsB
X-Google-Smtp-Source: AGHT+IFb27SR7odQ4toamoDL2JUxx/ntN7fFfoQDtzXZeAb/YsQCBOWoRBf1zDxHNAQjQW5TRnQeFg==
X-Received: by 2002:a17:90a:4386:b0:2c2:db48:aae2 with SMTP id 98e67ed59e1d1-2c2db48bc2amr7646274a91.40.1718112755759;
        Tue, 11 Jun 2024 06:32:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:ad83:b0:2c3:dc3:f285 with SMTP id
 98e67ed59e1d1-2c30dd33856ls1321406a91.0.-pod-prod-01-us; Tue, 11 Jun 2024
 06:32:34 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVhyxbVywyUBmMwqajOkSGLi1YbsA+D0zH5IV6jaCINy9F5YKOArJuG4sEOvFieS8hkRp9zV9ttbM90dddAikJBN1LeC0m/FZYSSA==
X-Received: by 2002:a05:6a20:158e:b0:1b2:4780:d9fe with SMTP id adf61e73a8af0-1b2f9ddf2f4mr13459469637.53.1718112754526;
        Tue, 11 Jun 2024 06:32:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718112754; cv=none;
        d=google.com; s=arc-20160816;
        b=vKp6rfECpEYJq1ML2Ackni2KtuGvLQp/CqRzPMAQ5pPNn3rLUeDPeF9DdCpme++jia
         V6rv/3ApYzHWi+q30AhMQJOXOnNK5x7JleaRDYXuNgppGPcY0/BiWzzOqHLbOKYNP7wp
         qrbm62cYoPfX/wpmAoPekOqzO/MT9N7eO2my4ZqFPPDaX1kZeA5VBp3OseT9Vv45eK5C
         37dDl5dP8GZMs8OBEMl0Be5lieXlGAMXX0Edf0eklP1R7655dMiKNZDm/XsEzojuR/9m
         sSiAVJwT/Fi5SeFtPrGpCXNJTQwI/YV2AMkNEzLMPxKu6ybLOwb5rdHxvRCuwjAJnRqm
         zVNQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=CczDrlzQ7X9eqfdK0+v+uqDqKtRnCLBrcF8URyssx0A=;
        fh=cIK2I4jjVXS2w27Pz25g2ETVoYhPAxmN2ecxVTILtx4=;
        b=fBBzREaWGLTLSB5KWjsBssZZ83fgIH2STGS1MCuE9nv2BhppOg66b6RXOvWX9wOBA2
         +b6oBBc1XgZxDZDXNMZ5zhTLAaRoTsKhA2oRt1YEuUgqIQdHBpvyw5LHX+MT/E4+Qw3J
         1dp3jpDUtBqd2Qe0aRI7FB1Um8YHazqlCCmNRdzN7txFjWGXLHbnUUDyrEdXDlYDAkKX
         pLEJ7CsYFYHgh13KOs5zqUG/30UlAYoTaly269gh9B5qOS388L+78ef/gWnRPiN6rnkH
         xUOXXTmzGayQAhyGWCue1v+M6Ae2R0LGmE0y8oHWYuykz62JbXR/vXm/1eNRPU+/xgJM
         EICQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=cP2SbfcS;
       spf=pass (google.com: domain of 38vfozgykcxabcuwyvuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--nogikh.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=38VFoZgYKCXAbcUWYVUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--nogikh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2c32fb50720si135974a91.0.2024.06.11.06.32.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 11 Jun 2024 06:32:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of 38vfozgykcxabcuwyvuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--nogikh.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 3f1490d57ef6-df78ea30f83so7454943276.1
        for <kasan-dev@googlegroups.com>; Tue, 11 Jun 2024 06:32:34 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVXRwTHy4hqtX82jrMIBqqiWLAxrP9c+C656U4CuHIV3MkTyjcsMfPxJOeutAzgtDvr6Fg/r8ovI42g4RrmambyFUOla4jb/VeO6A==
X-Received: from nogikhp920.muc.corp.google.com ([2a00:79e0:9c:201:4221:fb00:2718:295d])
 (user=nogikh job=sendgmr) by 2002:a05:6902:1547:b0:dfb:5bd:178a with SMTP id
 3f1490d57ef6-dfd9fc66fa9mr704907276.1.1718112753540; Tue, 11 Jun 2024
 06:32:33 -0700 (PDT)
Date: Tue, 11 Jun 2024 15:32:29 +0200
Mime-Version: 1.0
X-Mailer: git-send-email 2.45.2.505.gda0bf45e8d-goog
Message-ID: <20240611133229.527822-1-nogikh@google.com>
Subject: [PATCH] kcov: don't lose track of remote references during softirqs
From: "'Aleksandr Nogikh' via kasan-dev" <kasan-dev@googlegroups.com>
To: dvyukov@google.com, andreyknvl@gmail.com, arnd@arndb.de, 
	akpm@linux-foundation.org
Cc: elver@google.com, glider@google.com, syzkaller@googlegroups.com, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	Aleksandr Nogikh <nogikh@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: nogikh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=cP2SbfcS;       spf=pass
 (google.com: domain of 38vfozgykcxabcuwyvuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--nogikh.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=38VFoZgYKCXAbcUWYVUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--nogikh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Aleksandr Nogikh <nogikh@google.com>
Reply-To: Aleksandr Nogikh <nogikh@google.com>
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

In kcov_remote_start()/kcov_remote_stop(), we swap the previous KCOV
metadata of the current task into a per-CPU variable. However, the
kcov_mode_enabled(mode) check is not sufficient in the case of remote
KCOV coverage: current->kcov_mode always remains KCOV_MODE_DISABLED
for remote KCOV objects.

If the original task that has invoked the KCOV_REMOTE_ENABLE ioctl
happens to get interrupted and kcov_remote_start() is called, it
ultimately leads to kcov_remote_stop() NOT restoring the original
KCOV reference. So when the task exits, all registered remote KCOV
handles remain active forever.

Fix it by introducing a special kcov_mode that is assigned to the
task that owns a KCOV remote object. It makes kcov_mode_enabled()
return true and yet does not trigger coverage collection in
__sanitizer_cov_trace_pc() and write_comp_data().

Signed-off-by: Aleksandr Nogikh <nogikh@google.com>
Fixes: 5ff3b30ab57d ("kcov: collect coverage from interrupts")
---
 include/linux/kcov.h | 2 ++
 kernel/kcov.c        | 1 +
 2 files changed, 3 insertions(+)

diff --git a/include/linux/kcov.h b/include/linux/kcov.h
index b851ba415e03..3b479a3d235a 100644
--- a/include/linux/kcov.h
+++ b/include/linux/kcov.h
@@ -21,6 +21,8 @@ enum kcov_mode {
 	KCOV_MODE_TRACE_PC = 2,
 	/* Collecting comparison operands mode. */
 	KCOV_MODE_TRACE_CMP = 3,
+	/* The process owns a KCOV remote reference. */
+	KCOV_MODE_REMOTE = 4,
 };
 
 #define KCOV_IN_CTXSW	(1 << 30)
diff --git a/kernel/kcov.c b/kernel/kcov.c
index c3124f6d5536..5371d3f7b5c3 100644
--- a/kernel/kcov.c
+++ b/kernel/kcov.c
@@ -632,6 +632,7 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
 			return -EINVAL;
 		kcov->mode = mode;
 		t->kcov = kcov;
+		WRITE_ONCE(t->kcov_mode, KCOV_MODE_REMOTE);
 		kcov->t = t;
 		kcov->remote = true;
 		kcov->remote_size = remote_arg->area_size;
-- 
2.45.2.505.gda0bf45e8d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240611133229.527822-1-nogikh%40google.com.
