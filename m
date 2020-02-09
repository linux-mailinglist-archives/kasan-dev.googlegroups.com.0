Return-Path: <kasan-dev+bncBDCO5FWBMEILFGEC6ICRUBC2OKBAK@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id B1AAD156CEF
	for <lists+kasan-dev@lfdr.de>; Sun,  9 Feb 2020 23:48:18 +0100 (CET)
Received: by mail-ed1-x538.google.com with SMTP id g20sf4566890edt.18
        for <lists+kasan-dev@lfdr.de>; Sun, 09 Feb 2020 14:48:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581288498; cv=pass;
        d=google.com; s=arc-20160816;
        b=EB6vVhEtlohz+8j3p8I2lZHFuwCJA1pHuGlatFUn00HHWigMOmMAY2jA3yk0ULfAQ3
         vbK4Y+HHPcfxB9SmDRCnmOI9vQVCrkdcEgelumUTSExWhQYQ19e+GHIEzPMhvU4xwvML
         S5CldICKSUMpyeDjEUsciRc8H9cw2G31emD+Ohbq0HuNHaP5gwm9yAkWFZi85Wkt0le2
         c2rh0312+J+CQwJKI9uPHAj7IYh5397EOdyFGVGH1DWd9iMs+0EgE4K3BBuHEW9yozNh
         /anacXW4m8ICU2Oxcw6JGYf4QwHoedeTiet5WmpCsekKI0fPHnL+Aql+Uup8VCZ02uNi
         DXrg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=wBdemFHSLKxD4VPss/51Kb1q0kdTM/wUxhP75BTgnx8=;
        b=tSmfA6J8pmqAS9ZCw88VvV3m7MrTPoik9aR1oXZlLC2spqF8xjPyDO/pbbgB1ZJo+v
         tw4niAY98pMmo7fHDQtOeUgU+vGSyNOmtowEZMSn8AzgVi2BUo6w5GwFi/jY36jzHUrX
         R4lTT0KnDaj9hCCmHcCs+Kc8RnpEnOkGV+rSDM1YGfDmJ9SB4Er50eF0VXbmK9nMzIed
         FQEo834jBXzr2HSkQ2StV9hHaHVm1ewEcqhWYLrirqFp1kaVdJQSt4M+8V0dYjRE5vPS
         OeykUTVU1Xxkm+KlzYfWgijU2utl6Qr1o/qtVlxlrOtKGIVtfWOkRlEvU4PsR6upXWZC
         6W/Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=EkGmaN7H;
       spf=pass (google.com: domain of jbi.octave@gmail.com designates 2a00:1450:4864:20::443 as permitted sender) smtp.mailfrom=jbi.octave@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wBdemFHSLKxD4VPss/51Kb1q0kdTM/wUxhP75BTgnx8=;
        b=W2JJig8AQSKqsZoU/2MDbOU49yW+98/DLAUWNaN9awz57u9h1TzH9gWgkcproqVOAg
         NpOwAlFD7aOHInSoZuM/G3TPg3+nJ4CNEMavJN74ypCUB8hlbW9eJha1+R4wJki5j+5Y
         Sde+mN/d1qP/xaE8E2aCB8P/QsD22QciM5uQpeeM9OXP32rwRsq+eiCAiYpA40ca+JOf
         DddvsloeY1/9VHq8CGSpkhk4w0YQsY47YRZWunofk7ZoCf14iJpqPt6FT9RUI2c8v5Eq
         WL+W+917RrKv34Li7/zNE2/hZysm2f2iWZbKgU9IKFoQxd8OzimV/q7WoIvjzJUTFnrA
         YeRQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wBdemFHSLKxD4VPss/51Kb1q0kdTM/wUxhP75BTgnx8=;
        b=Jfia81f/RjAonnJNvA99veGEg0Simp+RVJnXahx9u2w9WK4Jq6xQWl44zba+xW2TFb
         kwwqJKdaEdeu5dqx9Ze2sM9Xefet907yICtdTNsDdtKHvlmv+o689uVV2j9n/pf0Dja0
         vCulLGdzLdi0RulQACoWLVVPCcFXnN74PI6eEPf0p4mcNYzwsfPKe1MbgrceH2sVswYm
         ql047MiaA4g8AYamnj3sVOPGVoVKi3/2Sf3olCtFGnSm2Iou6ilE0m8/68m5+TRJMRBV
         PxCW4yEz9NmkCyTmNSTDTAfVQxETIs/w0cWN1KGlGbFUaY0H1NrkYzQwenA08IubXEtl
         dV3w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wBdemFHSLKxD4VPss/51Kb1q0kdTM/wUxhP75BTgnx8=;
        b=TuyntAf8XnnYYuP/E4eIEfEVuNBEqzKx8Wn6Zs710Xbf2mTmoDaCAsHg+yIAh1wjC0
         q8Co5Kr4/o3a4l7kGZO36h/SQHLg3Hzc13hXMJcxDmu4Mtj5HJUULLgSPUK7CiatLqZH
         63frvsk0MfGouh412t8CAHMS38CwTZlQIiULr0nGsl4sBp82MkzUnAw2TwzemnjPikYo
         1AADBRHp4iHe8kMb3E9hJm6qo6o+wNgUGVbuSJuKg8bKDydYXoz4ziQCKxlMjMe37/Pa
         RVhFO25KidiKd5JMMDl6u2nOM+Hm/rb/tcDqq/u7mgikzzII6S2F3w+g+urgBgMnChGw
         m36w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVrE+cHOlIfXgsFMtgCVwR7jIMGQkmp4TvsqJ1eh46kfpLJOOd0
	7Spw5mfMEJ0oypwBcKPEXsU=
X-Google-Smtp-Source: APXvYqwCcysYpXRG1oOq0b/M5/bbmMx2OiJZbGNlVlCSTegM83Dc2ZQI+MEK24KCLnMXrGWqonZ/HA==
X-Received: by 2002:a17:906:d144:: with SMTP id br4mr9454150ejb.371.1581288498418;
        Sun, 09 Feb 2020 14:48:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:bfe7:: with SMTP id vr7ls3045841ejb.1.gmail; Sun, 09
 Feb 2020 14:48:17 -0800 (PST)
X-Received: by 2002:a17:907:212d:: with SMTP id qo13mr9158174ejb.376.1581288497796;
        Sun, 09 Feb 2020 14:48:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581288497; cv=none;
        d=google.com; s=arc-20160816;
        b=qVZ7iBNcHtJqo1620HfQd/9h7DBNf2vjWIQ9vH+jBULJADG/gJciuUydjsFeeYuaeP
         eJPbgcyoTArjo5dchJsu3znLTLlg6AUQGG4/2wnkgLJ6a6q3DlpFMFe/4UuD8ov/FCAY
         HpngW4AMVWiJb/HT+j+moU6dtgPeE4Fgb6dtKvP8Fnmb54HVA494ymKivG+6zY6WcUIh
         lBw8QYb6T+VxV4fBD5Br5smbRTMJC7s+qlmdR7feVOwfryrvB9iC9R9C35okjoZyL+Bc
         gfgFdZ1ebhKykjJr3HSRqkn+Ac5czMyxhG/P8wI6uBrZq1iZuit2pr4Rnj2ZJDoJvKnh
         IemQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=H5h8f3WgoxP68Q6jLjqnQAtMRjQkjB73Uemeu2QcLQ8=;
        b=E0YXpacdjBJH6i33QcxhH7TVtgvrl3YQxs1hMRtr5G7U8QIrOtNiCnyn0DfspKkK4T
         rTN+WTrUJB3uEr+K6VSqraO2PbNl4jvmUFBWRg1fmDn56yhqv5reo6G8MKFj0xDrem9r
         mvXRZ9JOvPlmKjtTKvcMUsDVULp5hFbIIP8k4MnIjOLOPUoiuvEJyMUnv1iT/wpUsH91
         8fDiysilO3oC/3pMcD4xHSKqCGu1p0hEorHapufrKlWbjwYVijucLBcu+GAoOdn29qoN
         gcSPczins3bk6rwvYJX3Z12/l/eJb0MDhT5G2SimGSzzrMLHRwAz85aMRCYbnxRh+22+
         jOrw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=EkGmaN7H;
       spf=pass (google.com: domain of jbi.octave@gmail.com designates 2a00:1450:4864:20::443 as permitted sender) smtp.mailfrom=jbi.octave@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-wr1-x443.google.com (mail-wr1-x443.google.com. [2a00:1450:4864:20::443])
        by gmr-mx.google.com with ESMTPS id z20si343830ejx.1.2020.02.09.14.48.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 09 Feb 2020 14:48:17 -0800 (PST)
Received-SPF: pass (google.com: domain of jbi.octave@gmail.com designates 2a00:1450:4864:20::443 as permitted sender) client-ip=2a00:1450:4864:20::443;
Received: by mail-wr1-x443.google.com with SMTP id c9so5253448wrw.8
        for <kasan-dev@googlegroups.com>; Sun, 09 Feb 2020 14:48:17 -0800 (PST)
X-Received: by 2002:a5d:494f:: with SMTP id r15mr13257456wrs.143.1581288497124;
        Sun, 09 Feb 2020 14:48:17 -0800 (PST)
Received: from ninjahost.lan (host-2-102-13-223.as13285.net. [2.102.13.223])
        by smtp.googlemail.com with ESMTPSA id p15sm12708938wma.40.2020.02.09.14.48.15
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 09 Feb 2020 14:48:16 -0800 (PST)
From: Jules Irenge <jbi.octave@gmail.com>
To: boqun.feng@gmail.com
Cc: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	kasan-dev@googlegroups.com,
	akpm@linux-foundation.org,
	dvyukov@google.com,
	glider@google.com,
	aryabinin@virtuozzo.com,
	Jules Irenge <jbi.octave@gmail.com>
Subject: [PATCH 09/11] kasan: add missing annotation for start_report()
Date: Sun,  9 Feb 2020 22:48:07 +0000
Message-Id: <1eca01a2537e0500f4f31c335edfecf0a10bd294.1581282103.git.jbi.octave@gmail.com>
X-Mailer: git-send-email 2.24.1
In-Reply-To: <cover.1581282103.git.jbi.octave@gmail.com>
References: <0/11> <cover.1581282103.git.jbi.octave@gmail.com>
MIME-Version: 1.0
X-Original-Sender: jbi.octave@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=EkGmaN7H;       spf=pass
 (google.com: domain of jbi.octave@gmail.com designates 2a00:1450:4864:20::443
 as permitted sender) smtp.mailfrom=jbi.octave@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

Sparse reports a warning at start_report()

warning: context imbalance in start_report() - wrong count at exit

The root cause is a missing annotation at start_report()

Add the missing annotation __acquires(&report_lock)

Signed-off-by: Jules Irenge <jbi.octave@gmail.com>
---
 mm/kasan/report.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 5ef9f24f566b..5451624c4e09 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -77,7 +77,7 @@ static void print_error_description(struct kasan_access_info *info)
 
 static DEFINE_SPINLOCK(report_lock);
 
-static void start_report(unsigned long *flags)
+static void start_report(unsigned long *flags) __acquires(&report_lock)
 {
 	/*
 	 * Make sure we don't end up in loop.
-- 
2.24.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1eca01a2537e0500f4f31c335edfecf0a10bd294.1581282103.git.jbi.octave%40gmail.com.
