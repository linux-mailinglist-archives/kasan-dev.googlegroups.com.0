Return-Path: <kasan-dev+bncBCXKTJ63SAARB6XTWGZQMGQEB4DKD5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id E9642909120
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Jun 2024 19:12:27 +0200 (CEST)
Received: by mail-qv1-xf40.google.com with SMTP id 6a1803df08f44-6b06ce632b3sf23707106d6.3
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Jun 2024 10:12:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718385146; cv=pass;
        d=google.com; s=arc-20160816;
        b=izLDwOGOJ4lGVJ1AEHQF6CYBAYDey/8t4t7RbK3NgGINxORcA4RexMtEh5LHl0G6gH
         G1NxHzPGw+Axu0BQNoVqmoM/hDIBsPuBOGcIoiDn4uHQ5Gc0SjkNuG/FmHCOKeuQg7ah
         95WMzB6JKp9iHWq5uWNwQXod5wjfYCQ9L6zM1IBbCM0wN42mjJeSYiMQOeSYCdsKaR3f
         N0tBtfcCXBua5SDDoyODKcOz4t5PImwsYOt+tS4IsJRUu/SvZAT5cPx/vLpwBSlHqqL9
         pPF6w1k9TmKNmk3Iw1hzQKP3o78nX0rMfL0EGpc7PqN6Mp1x/h0EwJdNJaKSjegnnUBz
         AS1A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=l+Xh2PGGJKptZnhgMsnj/sYBDzYKjDaMOqr7vEuznfI=;
        fh=JqaiAlpkLCUM6Bk1mU/aJBVsdQwVeNR4Ji4Yu20xv9E=;
        b=C4oaA4RHh63TG++jMkld2JEdpwn46eHminYhZHpdh/ySOMeXq7q0ldcPp+a+ONacDv
         JiZ5B1Tj2jRMESj0pGjyfFDE+Ss4k1ygrMN06VB+0sE4NVNzYs2omOKD4+yTUL9BS0Dh
         x0R8amWRuqDC1auR4W0o2rPpRglhaxPe3OKkGfTjoYH2uW9PVenX6CnRuD5PdFhmMpQl
         dR8M6fjYBk0VNrJP6kyA80drX12voaf25ca/yevE8j2NGeaBE0bPJe7O5UJB7wCpsb0P
         LoCgz9I8mCdnwAEqeNyynl3LCWiNn7o8qq+ye94fPN9md9gQ4+vcGFbCnLYy9zQSOOPq
         oujA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=P6GCtW95;
       spf=pass (google.com: domain of 3-hlszgykcdcgh9bda9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--nogikh.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3-HlsZgYKCdcGH9BDA9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--nogikh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718385146; x=1718989946; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=l+Xh2PGGJKptZnhgMsnj/sYBDzYKjDaMOqr7vEuznfI=;
        b=RcK8mJJr47PBzZVy728sJcvafCEMkNv+oZ4Lg9kRwadTeFZVONx1gBzShuPzgTcbnZ
         os+T3YkugSNB0qGvBA8Lxl2edXHJD8uxrQk7629ch0wx4pmkHXEOkSuqyPyw1tEOy5+3
         0orQ1S9pGn2VG2WnLwAKXoPsaCISodadgfF2zzoHVHfEf1lhFNQGMQsf9EgohP3fe+y/
         x+OV0kjr7GIdghc5iGk861kFI0u0QFL4O1tX6Z/eP4jaGespJ6sJtraWOt/bPZcwrYM6
         tV0xRqrwY6XniaQlYLVCEfpaNxi9yuKRps1C6QJQu64Ax50M1AI9H7N6n8vC41MzPxb7
         e5rQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718385146; x=1718989946;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=l+Xh2PGGJKptZnhgMsnj/sYBDzYKjDaMOqr7vEuznfI=;
        b=YZ5zi01Ow7CgD2ZoIYKp4y3wFCkR0PTcJU2hJo9xquWyH7zK2o58ViuFZQOBlF6s11
         Pl0cUaR4+gfRUfIHWdHBPYxZxCmf6dVRAkxRs3XUdwCxp3BxJpzoFMnQfy7qZrN9RA/E
         DbRHGHxzFyxEOHIvT68LtiK5iG+LNeqHchmzVtjmixoi9GQD85XcPGPobJYC8+CWtmLs
         f7qhg+jbpCHuhahQEircLcSjrp5sh5HuYfPl2Tso2pHeJFp5wmeutymDPmD5yTHlLARe
         SP+7wFgm3fXFpEUaUTFb8oK4dkIGCzyyl+Qvr+uyQVQuFePhT9xr4WOCv9bAV8Nw25Rs
         pIMQ==
X-Forwarded-Encrypted: i=2; AJvYcCXKlVqiLsIuL6XDHPsquCrtzaW0AS0mYv3jm4A/uUoQqmrjVCgojVYWt66ax5RxyaCAPA5F5LBS0DT4CuMGQeJYNydFZhjATA==
X-Gm-Message-State: AOJu0YwwBCrqipMbbX3cCkeszg1oaoOnfWTaQVC5TNRFOzEzhuew+Iwn
	1TOHmdZ5sWhzq4qUWMMDeB9z0FU1bFyswIVy8m739pOQiCSqvhb9
X-Google-Smtp-Source: AGHT+IE92gzKVmzGcq0QdyCcq7lJQ32LCaB8TcOWB7fJUFS9kwk6zmgQH75NDXS9PtdD5tTQXfyJaA==
X-Received: by 2002:a0c:e845:0:b0:6b2:aa66:9a0f with SMTP id 6a1803df08f44-6b2b00bfa36mr32607806d6.40.1718385146180;
        Fri, 14 Jun 2024 10:12:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:59c5:0:b0:440:29:dfea with SMTP id d75a77b69052e-4417ac3c9ffls31452891cf.2.-pod-prod-09-us;
 Fri, 14 Jun 2024 10:12:25 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXARI/nazZrKCUaT2YLfvGQ7dxyeXMhkoeSAlyhlyijMaUkp5LwoY4myZRFIHchHVLLHFBeyZROSpKwxPPG0DksKayY2TIN6QE7ng==
X-Received: by 2002:a05:6122:310d:b0:4e4:e9db:6b10 with SMTP id 71dfb90a1353d-4ee3db8b0f0mr3976459e0c.2.1718385145345;
        Fri, 14 Jun 2024 10:12:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718385145; cv=none;
        d=google.com; s=arc-20160816;
        b=VjTilkO5VJ1EcT5iLgYiUtiMpRx3VMLrhHhcA8YAxs1PmaliEe6Pb5I4jH+ssq8HEU
         xsy/QsRXYIwXP+UTOc3Xr/aMlhBE8CLXLozBTe/P5LkwAvElimPGLgQoXLNUSR2B98w9
         s7s6fiucDl2h5/0XYM78rkyTkGQu1ci+b5UEFGNPsYdWlS2Fp+uD0CaDf6limgKezLs4
         goyx872eibOjcippKHBsHHOs2KNjQ4mRAN4NcB3f++oPu4wqs5JIoAwNNXC12+GFlGjF
         p91jXtH6V+w+jJUvEfTGJWw94YlNNQBPWslVGwbgWuCcK8OwGGG5uSb3d3fdHm0CYjhC
         fUUA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=emwuEUJzOe3CVEz416PelL/kwtt17NFvxEL+ya6n9Ro=;
        fh=voc7PbVSbbcxiAPY6SUWheHtDM/1zVV+W61ZSZ8Ma7k=;
        b=lidkSg79MTMxJjF24EFCI7cWfpYJzsXQfDoe4SgNtfnkNjkeDHkKPkjvnVqCoVa5ww
         fbQkGsd02vjmVAxFNwSD3Rf4liG69pUg1jHtMlfV7g9W0JSuNhboonozeNS4a3omTy89
         YN28ATQKwaqm9T3NkUHdiiiNHje/yAaoywOKoIPa/duXtzHUOWgIQfeKS1U4m93UIR58
         9i/mvd9bP87V76fQ3fheik+SYItOAuEgXU4DL0s5cPmGRgd35QRcLsLFhMznsmrreROF
         VJNw5w+YSzpkmjrJzzVlxhJcFxcRIMosLm68OcxDKXWfk/cxB6hcj5HSIb12V5aS68QL
         x0vA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=P6GCtW95;
       spf=pass (google.com: domain of 3-hlszgykcdcgh9bda9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--nogikh.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3-HlsZgYKCdcGH9BDA9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--nogikh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x114a.google.com (mail-yw1-x114a.google.com. [2607:f8b0:4864:20::114a])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-4ed3f7cfa7esi259157e0c.2.2024.06.14.10.12.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 Jun 2024 10:12:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3-hlszgykcdcgh9bda9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--nogikh.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) client-ip=2607:f8b0:4864:20::114a;
Received: by mail-yw1-x114a.google.com with SMTP id 00721157ae682-62d032a07a9so45002067b3.2
        for <kasan-dev@googlegroups.com>; Fri, 14 Jun 2024 10:12:25 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUtQ2jb+1esoWQzkS89Wbf6/pfoyBUKw4kQgVbybVkaCngYNOruP3I8Z26oWZmYl+WlwRX/SK+QOVmZvWSTZbZ5QVObMWjd7GD5+g==
X-Received: from nogikhp920.muc.corp.google.com ([2a00:79e0:9c:201:4f99:8d17:1a35:c8a5])
 (user=nogikh job=sendgmr) by 2002:a05:690c:d1b:b0:61d:ece5:2bf with SMTP id
 00721157ae682-6322265e839mr10188807b3.4.1718385144853; Fri, 14 Jun 2024
 10:12:24 -0700 (PDT)
Date: Fri, 14 Jun 2024 19:12:21 +0200
Mime-Version: 1.0
X-Mailer: git-send-email 2.45.2.627.g7a2c4fd464-goog
Message-ID: <20240614171221.2837584-1-nogikh@google.com>
Subject: [PATCH v2] kcov: don't lose track of remote references during softirqs
From: "'Aleksandr Nogikh' via kasan-dev" <kasan-dev@googlegroups.com>
To: dvyukov@google.com, andreyknvl@gmail.com, arnd@arndb.de, 
	akpm@linux-foundation.org
Cc: elver@google.com, glider@google.com, syzkaller@googlegroups.com, 
	kasan-dev@googlegroups.com, stable@vger.kernel.org, 
	linux-kernel@vger.kernel.org, Aleksandr Nogikh <nogikh@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: nogikh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=P6GCtW95;       spf=pass
 (google.com: domain of 3-hlszgykcdcgh9bda9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--nogikh.bounces.google.com
 designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3-HlsZgYKCdcGH9BDA9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--nogikh.bounces.google.com;
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

Cc: stable@vger.kernel.org
Signed-off-by: Aleksandr Nogikh <nogikh@google.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
Tested-by: Andrey Konovalov <andreyknvl@gmail.com>
Fixes: 5ff3b30ab57d ("kcov: collect coverage from interrupts")

---

Changes v1 -> v2:
* Replaced WRITE_ONCE() with an ordinary assignment.
* Added stable@vger.kernel.org to the Cc list.

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
index c3124f6d5536..f0a69d402066 100644
--- a/kernel/kcov.c
+++ b/kernel/kcov.c
@@ -632,6 +632,7 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
 			return -EINVAL;
 		kcov->mode = mode;
 		t->kcov = kcov;
+	        t->kcov_mode = KCOV_MODE_REMOTE;
 		kcov->t = t;
 		kcov->remote = true;
 		kcov->remote_size = remote_arg->area_size;
-- 
2.45.2.627.g7a2c4fd464-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240614171221.2837584-1-nogikh%40google.com.
