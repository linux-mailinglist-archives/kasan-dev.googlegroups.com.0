Return-Path: <kasan-dev+bncBCXKTJ63SAARBBUSRCHAMGQEXI365BI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 9ABF047C494
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Dec 2021 18:04:06 +0100 (CET)
Received: by mail-ed1-x539.google.com with SMTP id h22-20020a056402281600b003f839627a38sf7078998ede.23
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Dec 2021 09:04:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640106246; cv=pass;
        d=google.com; s=arc-20160816;
        b=M+LY/kXvuz1CpMb/r24LiPduTtER5FPUZcbIkiWZoX+ucj+XHGx1cfkkT2jAfDGvgU
         LYmriJSRCndz+5BMyhKrnWld3+vX+VyWkPl/Io7GI2gJViPvbS+fetv6w6Kkis/9FmkN
         PiCYSD89BgfOeq9IF2yr6e0cwFTNjExON2T1LGs3NITMRqbejC0GTY2xb8AsqZ3qa1eY
         L81upcI2MZQ7b5uPp5Q/EulzhX4Y+s+fi5hs1JrBKocqXYmLYpHcLZvk9Yk0OMct4h0v
         69CShZ8FTaOpG/r6AflTxG6wBbixRMweRKSMvA7GZFUp5KqOfbUCsGOOFZTNhK0J9AHy
         JqfQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=e9WxVWyiNNRv4g5OCnpEdQRi0Q+LHML75ReNtCSbo/c=;
        b=MQh5BO01753C3+efcOsRQVbEHtBgxoKDBY9UBXw7V1sqCUhyuAxa33x6kN7i3ehV8v
         /ePTw9ecH8HGd10EGCkv/fiJOS37dYqo1jLg37l2yPHXyC6b/T/2XYPKASwsHBqm26Ub
         EeiSBQeOCte2zu/IwtXWbdvYfLSws/rogl8gi75i5WGPswdzX62Su/GEoLG7cOj7eaWJ
         jScEuEfmJB0c/s7ivwR7zYDOfpE8hpF4MVmGlNZTuYnB8gc/TqCqhm0NlIQIKCzzd5Le
         oZaerPSyHAk+MkPu/APJ1Wo8Yjwnzr7pPSKhCdKc5B5s31dgGl+o8jm9jW4/yfz74Ne3
         qL+A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ZnB62cmm;
       spf=pass (google.com: domain of 3bancyqykctmcdvxzwvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--nogikh.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3BAnCYQYKCTMcdVXZWVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--nogikh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=e9WxVWyiNNRv4g5OCnpEdQRi0Q+LHML75ReNtCSbo/c=;
        b=C4h7yPsdXEPT/aPQH5QXjYocV2xMpC2nxbfes1o9THJ3gFMB2/k8nFSWDQ4qNy4q3k
         ibHvr8nTbAYq/hr6S57Zfewsre2dvbNXQsGw2aMvKt1n9KEFJMJhW8X0l0D6RN52lki1
         lbUPCGVwTdwWFvSLfqqaUw1y0pKxFO7xCoqUhH2oqWOP1fW7m6FW6mFQXo+cKLPPDInE
         by4gE0F8Th/w1YEQUr1nS7CzSUaw+wrbJ2U7eP6BTmMCUx3NSX30foIX4YKSCwErF1gW
         AIajpCQ7FgtcuEDkloTnBKr0Ew5vjJmoiAiU7LCYFasQmdpMDrIMpyfkeiANoxEhkWpV
         4FNw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=e9WxVWyiNNRv4g5OCnpEdQRi0Q+LHML75ReNtCSbo/c=;
        b=IFjwLQZeqm/y9Bc03+iCrQvShudDfUwHVoA5XszHUEWt+xmsaTYxVw43WkOe0EhTb8
         jUktvL99+Q7GBfDa+4asSYktVLc036tgN8gx3yfNSrkW4YT05JmRVohtDHA4QIXkPNyD
         W9tjK8BTJXNjP+jfszUOkBMMxG9uSJtimiEk8zGV/hpihvnHgnl5gt9drClmSSclMgqz
         8gpkD+SzH8PLR+j+H9/HbCz0dVT9+H6vtiZP7u+ArMynG3oJrHLkf97Eu7yvByO66SDc
         oRyqZomBre8iR7AHr7IWgbME6qxA8EBSKaYHwdZcmVAsrthdj9DWNJNurS+fHZyb0sjj
         a6yQ==
X-Gm-Message-State: AOAM53399b/8vwjSWW/2jXuTom4DQQ2yUdWGb2QeNRn0BXJZ4xwAdM6Z
	2ckZn16ekimdteV2qu0uQ4M=
X-Google-Smtp-Source: ABdhPJxO6syf420TF4AzxuorlLDnLlNmOEf5fqQjkMpZ8LrZAwvE3jfGfnKXnZZ6CMaqWOkOvXNlWA==
X-Received: by 2002:a05:6402:177b:: with SMTP id da27mr4192164edb.82.1640106246285;
        Tue, 21 Dec 2021 09:04:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:2691:: with SMTP id w17ls2972221edd.0.gmail; Tue,
 21 Dec 2021 09:04:05 -0800 (PST)
X-Received: by 2002:a50:9510:: with SMTP id u16mr4216328eda.134.1640106244828;
        Tue, 21 Dec 2021 09:04:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640106244; cv=none;
        d=google.com; s=arc-20160816;
        b=lAd/vzB5BIzBs0FsciTiwx11svFmvGfcOtRVOCkHv65Wu4rnj99cjGHyj7QaxMkACm
         wskm4kJmdu89aobaVG/BPzFN6ZiDXymOIf30l3E4QCJ+AOpXehRwhdhXtBhJkRe/uUUx
         W/jDqVpWbfATZSJ8B2sdpXd1equCqreBlDlTXjUGji/Iska/x998YqeJFJ84+1K3pnbG
         tQcv38YVgStQmMVi8kuHr1bjaY9T1B9YvhmPw2Yc4ZXEq39oevZD/HAtsN5kv2lO7kaV
         qVQDi3AEHUmMS6O4E364IqEsBSftSa2Ou7+uzRFEshoA7utng6L6RbG/rpnfnpgKTwfs
         iLyQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=5MCgdl+g0Q4ZtcQEoUIl/+nsdYtAzp+QkVH77bfwlh8=;
        b=CrzNelBIoNrOujG/lGJgUC+BxAwkXGM36NYkQVeGyHDbYTyDAPW3Y5LqVy5q7dHJf4
         EkrVdZ8hEaaDAFgCzAzzSEjru4MPARYPoLM55Q2NrdKKaPqKO/urTavdLi/7XSLKyxnx
         FQRybXJLfg6MW9jzMCxutYLuxNEtoesmLXbcGIr6ScMChzKO8vq+SBIOowNm8Aa+vS7i
         rYRRBBFjDFg7TncQo3TrPZ0jmzD706RM1ksA9sdqnqv3EfjeYrglShPeukPtOh6V0ZES
         b15vpVK1Emvlm5iDRmduvIYXywuXINiRK0VWnhpJvmmKW1JMzxmOjjDPQFK8iMeQaXdw
         zSmg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ZnB62cmm;
       spf=pass (google.com: domain of 3bancyqykctmcdvxzwvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--nogikh.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3BAnCYQYKCTMcdVXZWVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--nogikh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id eb8si1078875edb.0.2021.12.21.09.04.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 21 Dec 2021 09:04:04 -0800 (PST)
Received-SPF: pass (google.com: domain of 3bancyqykctmcdvxzwvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--nogikh.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id j207-20020a1c23d8000000b00345b181302eso1538688wmj.1
        for <kasan-dev@googlegroups.com>; Tue, 21 Dec 2021 09:04:04 -0800 (PST)
X-Received: from nogikh-hp.c.googlers.com ([fda3:e722:ac3:cc00:28:9cb1:c0a8:200d])
 (user=nogikh job=sendgmr) by 2002:a7b:ce83:: with SMTP id q3mr3537858wmj.37.1640106244487;
 Tue, 21 Dec 2021 09:04:04 -0800 (PST)
Date: Tue, 21 Dec 2021 17:03:46 +0000
Message-Id: <20211221170348.1113266-1-nogikh@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.34.1.307.g9b7440fafd-goog
Subject: [PATCH v2 0/2] kcov: improve mmap processing
From: "'Aleksandr Nogikh' via kasan-dev" <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	akpm@linux-foundation.org
Cc: dvyukov@google.com, andreyknvl@gmail.com, elver@google.com, 
	glider@google.com, tarasmadan@google.com, bigeasy@linutronix.de, 
	nogikh@google.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: nogikh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=ZnB62cmm;       spf=pass
 (google.com: domain of 3bancyqykctmcdvxzwvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--nogikh.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3BAnCYQYKCTMcdVXZWVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--nogikh.bounces.google.com;
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

Subsequent mmaps of the same kcov descriptor currently do not update the
virtual memory of the task and yet return 0 (success). This is
counter-intuitive and may lead to unexpected memory access errors.

Also, this unnecessarily limits the functionality of kcov to only the
simplest usage scenarios. Kcov instances are effectively forever attached
to their first address spaces and it becomes impossible to e.g. reuse the
same kcov handle in forked child processes without mmapping the memory
first. This is exactly what we tried to do in syzkaller and
inadvertently came upon this behavior.

This patch series addresses the problem described above.

v1 of the patch:
https://lore.kernel.org/lkml/20211220152153.910990-1-nogikh@google.com/

Changes from v1:
- Split into 2 commits.
- Minor coding style changes.

Aleksandr Nogikh (2):
  kcov: split ioctl handling into locked and unlocked parts
  kcov: properly handle subsequent mmap calls

 kernel/kcov.c | 99 +++++++++++++++++++++++++++++----------------------
 1 file changed, 57 insertions(+), 42 deletions(-)

-- 
2.34.1.307.g9b7440fafd-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211221170348.1113266-1-nogikh%40google.com.
