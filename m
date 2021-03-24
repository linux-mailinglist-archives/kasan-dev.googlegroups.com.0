Return-Path: <kasan-dev+bncBC7OBJGL2MHBBOGD5SBAMGQEDDARSIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 1DDD0347718
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Mar 2021 12:25:45 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id z12sf361282lfs.15
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Mar 2021 04:25:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616585144; cv=pass;
        d=google.com; s=arc-20160816;
        b=ar6She71V1E6x+zyIaGqYpkma9K7UJpGWpNOG3GXM4dJYSXhgUTMsQ3vGjDmOGjEY1
         Et7FYu27jAOz8YZLV56ytYSjEW9No3xpSrLLmFXEo7g+SXTfbDyFv7j+xQ9mQRzesYBQ
         M1ka2R3WzyrQz0WmzVT6pA6r1UjNTIt2A8kvJLDnCvM8Q1GvomqHINBNODINuuOpIVw/
         Y3iSkr05/hoL9bmtwdo7/W9aejs91ied6p6ZRBzj3ObjZVe/zFO8eGrIL8UOHsaOS9Uv
         Dy884bm0RZ+/f39FU1eB7Vw+2oZlX3diwzuPxBhTpMbL1bct2VFS7jYCMxnhD9Tcelex
         rBoQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=lWd1qBGejeU0ZhYYaE0lArnuO/vXgXBLT03bk6NchoQ=;
        b=kwufjwBjXl1zSr2K5olR2rZUYSwrvdJoXVwoFCtJmgSD88RRORtZZE5ro/Sbr9fGHz
         I9I+9TM3nNK5XT01brNU6dAppoCW9zcN/qC/+rl937/Z4HoizwIhdCw6W6wAFNlC8Isp
         /bx40NAtHDdjvfA5VNzOuxyS+FLBn+bpJuXqEZBC3f19x56jrfYHhrb6WGUzryjHs+dx
         Ipfgzte7qpIrG6W5s5OFD9BF0AAR9JVU9ysqrnYPluHbmLMwlJBHlRlwA1gp/927G5H3
         /0QwbosWBUfn8eNB4IIOwx1KKkc3WwuRb9cCgtNpOByaZOpfOGwJXDY/ArZurCLzE7Y8
         lkcw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=kv7CiN8W;
       spf=pass (google.com: domain of 3tyfbyaukcxaszjsfuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3tyFbYAUKCXASZjSfUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lWd1qBGejeU0ZhYYaE0lArnuO/vXgXBLT03bk6NchoQ=;
        b=ryJeZDss4F0yZyKUUVpcDYVnoRWvif155sO343myTpT/KP/deRfMYE4gINoZARN/P8
         mBEPFo0kjQS/03iqNPr1Yvo5xdoMMCnz9c6QDxaVsv76NTL9qYZpb1jXiRCriH+WQnSA
         0J9fqEvZ3vx8FEfnm6uWoRF2he+8tNi3lVdyVdOER8Cxf9CPSqN+zRmcXpTnAqYNNax9
         qF5gqDse2TVg54n++GPqnjxSUpAL4sA91W3vIBSnydgJcPEDQxQW7+iEni4tBp5hC5ny
         tOPlGeBsr4csnUaiExzOqazFs1nKCzzTjhh+126hiHsOmDv7SxbsEQ7EYswUSjjuaOot
         DxGQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lWd1qBGejeU0ZhYYaE0lArnuO/vXgXBLT03bk6NchoQ=;
        b=pa5PqWodesbiOzV9+mk5aLJoWJUsZuVnEY0VzHSUo5lZe2s5AEltGHGtg++WBS+Dti
         WB7UlhKUBDCbnEy+XZj2w7UuIm4w9Elu6x48WcQBec8ZF8rBqwEnKo36NqlrScweDi5N
         MKmot7a9k36PDPOcPxwPHrnLrXhImvuFVtUhbFk/SoBlZxfS0S8hU2tLijvPww8Pe6V5
         vWU7ZNDR1IV4PyKzL9T7nS8o+4Ds5L5a85iErbLNg9XQYDXDPIccU7wHdYVkyS4Eym6H
         HqF6iPW/sCPPajh1JLKHwFrpqAyOc7tIV6DQ6Sedz+d59KqYJO4C/bYFdlLj75vLuKp+
         z+Sg==
X-Gm-Message-State: AOAM533rbdA36tZoTESFyBI5EfKJAihE+KB0IW2g/1ogLm1nzMp763cG
	N6qcKe4vNc3VpH7a9WsDvOY=
X-Google-Smtp-Source: ABdhPJxtbqq/vTk91CF+bJNbAscEpSlLJEVseFRxILMY3m1yudhy74AvGMuc8hYDS/dBAF5QsVNmCg==
X-Received: by 2002:a2e:9899:: with SMTP id b25mr1819499ljj.376.1616585144646;
        Wed, 24 Mar 2021 04:25:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:6c2:: with SMTP id u2ls1319082lff.3.gmail; Wed, 24
 Mar 2021 04:25:43 -0700 (PDT)
X-Received: by 2002:a05:6512:3590:: with SMTP id m16mr1690038lfr.417.1616585143509;
        Wed, 24 Mar 2021 04:25:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616585143; cv=none;
        d=google.com; s=arc-20160816;
        b=MXyocRbxNJ+17ft7pRoLWC//6wjc53ZyxGR9+NmRhnK4CuwbwKDm6qsXY+K159ETi0
         61MntAHh5xbGICNF/osRzykCA4FZ3YBNbSNccQWpy5XYbb/1aoXCkCeVvlPLLg744gi3
         iY1F52GKf1GgQxt6l1HSiFFZdTXIlK3Z+4OJkOdirxVvZlLavUEEwiuq5r22AxHWwgqO
         JEVuoAsN39FIl2iKs25rz2JCRlQfEjn9ixaAh5a5WugdE0YhwII3frK2H3pdOEyMc0Cb
         K/2tmy7hrpd3BYRwTsfKD2APJo+T8rm4PUOQ+oHsL84ZtJ4moDIG1bsZ0lNMNguuRpBo
         4gWQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=I1KbrT5XqAYTtTHNgD870993nANc6M+4kCGSgsFMdj8=;
        b=zW03zJG210FkOth/Y9ZLh3fPHWUxbkT4n12PWSzbbsNWWSepuRg6qTbjgzQTByO5Xn
         qB4h6RT0In9AQLWiYWT2by3x0NzLW3tAFdaxsZ+aGrxg9ouJ1YJ8SoKCt85vvsCduZz6
         iZKUcpAMs5XOMD79qzXlRZRb7fhCeyGwrrAuohcKc2vE/KAEO9PIfc0xkIO1n4L4Jlve
         Wemw+DLtc6Tr3imnNJ9FPoOmTu+cONJtgFZiDDfBrCMC/okLOL+jXe4gJYcHqfSMhxkl
         vQZ6pmkI65UvO1cYX7Xjaxtzbq/0JQQmONyJ/KBHlatFixfhwOZ60NggDjTIgXtAP7x2
         L+0A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=kv7CiN8W;
       spf=pass (google.com: domain of 3tyfbyaukcxaszjsfuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3tyFbYAUKCXASZjSfUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id 63si74716lfd.1.2021.03.24.04.25.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 24 Mar 2021 04:25:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3tyfbyaukcxaszjsfuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id 9so935330wrb.16
        for <kasan-dev@googlegroups.com>; Wed, 24 Mar 2021 04:25:43 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:6489:b3f0:4af:af0])
 (user=elver job=sendgmr) by 2002:a1c:bc56:: with SMTP id m83mr2462445wmf.174.1616585143013;
 Wed, 24 Mar 2021 04:25:43 -0700 (PDT)
Date: Wed, 24 Mar 2021 12:25:02 +0100
In-Reply-To: <20210324112503.623833-1-elver@google.com>
Message-Id: <20210324112503.623833-11-elver@google.com>
Mime-Version: 1.0
References: <20210324112503.623833-1-elver@google.com>
X-Mailer: git-send-email 2.31.0.291.g576ba9dcdaf-goog
Subject: [PATCH v3 10/11] tools headers uapi: Sync tools/include/uapi/linux/perf_event.h
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, peterz@infradead.org, alexander.shishkin@linux.intel.com, 
	acme@kernel.org, mingo@redhat.com, jolsa@redhat.com, mark.rutland@arm.com, 
	namhyung@kernel.org, tglx@linutronix.de
Cc: glider@google.com, viro@zeniv.linux.org.uk, arnd@arndb.de, 
	christian@brauner.io, dvyukov@google.com, jannh@google.com, axboe@kernel.dk, 
	mascasa@google.com, pcc@google.com, irogers@google.com, 
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org, 
	linux-fsdevel@vger.kernel.org, linux-kernel@vger.kernel.org, x86@kernel.org, 
	linux-kselftest@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=kv7CiN8W;       spf=pass
 (google.com: domain of 3tyfbyaukcxaszjsfuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3tyFbYAUKCXASZjSfUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Sync tool's uapi to pick up the changes adding inherit_thread,
remove_on_exec, and sigtrap fields to perf_event_attr.

Signed-off-by: Marco Elver <elver@google.com>
---
v3:
* Added to series.
---
 tools/include/uapi/linux/perf_event.h | 5 ++++-
 1 file changed, 4 insertions(+), 1 deletion(-)

diff --git a/tools/include/uapi/linux/perf_event.h b/tools/include/uapi/linux/perf_event.h
index ad15e40d7f5d..3a4dbb1688f0 100644
--- a/tools/include/uapi/linux/perf_event.h
+++ b/tools/include/uapi/linux/perf_event.h
@@ -389,7 +389,10 @@ struct perf_event_attr {
 				cgroup         :  1, /* include cgroup events */
 				text_poke      :  1, /* include text poke events */
 				build_id       :  1, /* use build id in mmap2 events */
-				__reserved_1   : 29;
+				inherit_thread :  1, /* children only inherit if cloned with CLONE_THREAD */
+				remove_on_exec :  1, /* event is removed from task on exec */
+				sigtrap        :  1, /* send synchronous SIGTRAP on event */
+				__reserved_1   : 26;
 
 	union {
 		__u32		wakeup_events;	  /* wakeup every n events */
-- 
2.31.0.291.g576ba9dcdaf-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210324112503.623833-11-elver%40google.com.
