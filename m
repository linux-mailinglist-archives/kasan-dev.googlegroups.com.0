Return-Path: <kasan-dev+bncBCXKTJ63SAARBX7IUWZQMGQEITH53FI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x39.google.com (mail-oa1-x39.google.com [IPv6:2001:4860:4864:20::39])
	by mail.lfdr.de (Postfix) with ESMTPS id 49F7690502F
	for <lists+kasan-dev@lfdr.de>; Wed, 12 Jun 2024 12:11:45 +0200 (CEST)
Received: by mail-oa1-x39.google.com with SMTP id 586e51a60fabf-24c501a9406sf3638175fac.3
        for <lists+kasan-dev@lfdr.de>; Wed, 12 Jun 2024 03:11:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718187104; cv=pass;
        d=google.com; s=arc-20160816;
        b=EGdZ6w+3UHyVTtKw7TqCq8w8c/jXpUGF+znv17OvBNjtgVEyYLPG+vSwZgVtOcysdA
         TYFwux5IZvXccmSSMogKRWexshGgal90k1Tp2SxTpM6MO5UDEp0devjBfT7QnGC+Jiz4
         +KkZUUy7NxV4IyHFm2ATCv+zVQX0aIGKahbE0lXkXvms/Xfa6ISltDPybgHkW+8zxyIP
         PbIf7dHoKTZ+yHXNLudkl7VCcH0LFK8Qio8alrizVzzZwFirgBW426ySHmxk34Up/seU
         162x27j7e9iBeeuFtiGMvauDjp5CblaZLNJmxc4fqgC5BM/O5QbS3bMVRwG/Hp6YpRoQ
         E3Ng==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=cfp7gx2F6AF/zc1NkDgAWdstR1daJlFIf+bcgDXRXJY=;
        fh=L5VyfQc/8T/E2Q7jRJB5M34w5EYtzBM2uzdkOsLI+qQ=;
        b=diWqbpuM36joyFwG0rbdrWVcS/5Bt4m+k6vocFweOrwG2aNwkVCvSUtkXTtkDXtg5B
         nK/VYeKy/eL1/cJmhqcZce/4adE7k6FplvLt1mu9oN7aAiyqzo4B8u2d+LmNoywnuSfz
         if4HYksQnauC5+BWa4jIKVMf5vajWD5VI3uHJbyCK7Y0dsVwNujwOp3nSOW7N60QRA0C
         1V+UdykGWnVNpWJGND09ppSyjARGuppevdoPWJ6wcGaPsIWVb4IHe545HX6lQLfe+uVU
         1js6/AeoI6vOdnDNlCurzILsM50C5lyhCodY4gJ0SXJF+iBZ03Nh6UTqy+NMfyd5Gb+x
         yAvg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=qS+uN0R+;
       spf=pass (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::62a as permitted sender) smtp.mailfrom=nogikh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718187104; x=1718791904; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=cfp7gx2F6AF/zc1NkDgAWdstR1daJlFIf+bcgDXRXJY=;
        b=r7Pv8IiSLzbge5VXXK+a6UTsv+k7KHJXrct/5a0rnIiQPpJI6AcmZYURrKY4r8HRdF
         PT3xD8bUCJKoMrWC1juBKjcnJ7KzixpSOB0k2Yk+2Q1JhRf51KBs47Wdb3skjFl6Y8Zf
         KlF8x/IpwCBIz1c7YTF/QlYNHZP+cmgRccvz7xDY/yBMsgM5c3uiMTcIkhYLbjZBzLrT
         L1I9ZGR5cKlyZ8gitX3jFcGuw+bHFzZL+r6hl3CIBzdaHVtjKmMqhBUqC3JbGDwyaFEU
         Z1+OioUWUEo3R68ka1il3PxnoejGHgTFTkrPGmx3lsgJlsOrtXflAS+KUl7YyJxCgrTT
         tZ4A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718187104; x=1718791904;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=cfp7gx2F6AF/zc1NkDgAWdstR1daJlFIf+bcgDXRXJY=;
        b=OsWOn1fIZg9VGGPtJVnaXrSLGwFFd+jRJPWgas5YhCSwMJUYkQdi2Uobu+dcOKE84F
         +Dy6/afipba5iFtUUMDHXpa+VyGwciR3mZ6SLxGP5Ch8yT+6u8dGC5fj4CEmrT83xaXy
         DcddOG+0WFKne8ny4PSkjXfbfakwb+aY2Z2uIbOTQqzBY/rTLQ+k7hWFBEL+KRCieQ+d
         Uw5TGF3mXu0azQTJdoNjstZvMTFE0+Z+Yo1E0EOsL70+EStSvn5EHJnUs1QD6V8X21Gn
         QkyzEwRmRFxbTIDe6paLtEJuz3XSZsR2bV72kheVd0NNaqrwQ8nIaKxTFjqEioiN88lP
         b0Ig==
X-Forwarded-Encrypted: i=2; AJvYcCWlOqcKJq1+wdQZUeQnKEvymc22LLAmszYAolsTTiLQyQPLvN3xXivYNMhVL2LHcUT1SKY4wB0w9yMzwhKIby/SjLRwZMYGXQ==
X-Gm-Message-State: AOJu0Yxdnla73qcFCiRtvjl9D8/8EWkMKPZNV5AxLapgap/8oWEP/wCV
	JpDRkkyHrSCUxcEPuncDCRccWfj9/loXNfBiM8K1OL1iPxARdKMw
X-Google-Smtp-Source: AGHT+IG2G9YG3KLMgD8uu5x0BBsdKG3I+H6OvlWZAq4WPepM17bnTnSXd72vilPyvZ/25TR8O8UFxA==
X-Received: by 2002:a05:6870:8a0e:b0:254:a2bb:822c with SMTP id 586e51a60fabf-25514f210acmr1377469fac.43.1718187103615;
        Wed, 12 Jun 2024 03:11:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:b493:b0:24f:f0cd:4790 with SMTP id
 586e51a60fabf-25481fea57fls4761027fac.2.-pod-prod-04-us; Wed, 12 Jun 2024
 03:11:42 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXRKQS10p0wsl1KUhQmtgiNa8hKPadr4VvJJRuXulAQiZ4+kIj9/HTLj+FOE9k1mgdg0BVVDkQ2Y9gddnEH8y1fst/uGSaPDEXKpw==
X-Received: by 2002:a05:6871:5882:b0:254:7471:56b7 with SMTP id 586e51a60fabf-25514c035bemr1259937fac.11.1718187102656;
        Wed, 12 Jun 2024 03:11:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718187102; cv=none;
        d=google.com; s=arc-20160816;
        b=eGJja7slFHESYbcYsnjpcaPLpzpr5k8N8Eamk6SOxvbygW/ksunpATw7y4e0zIgGHe
         vOahvARsTVf8gX8LwBagVGHBFEvCl54UWqaKDAO3ue8owKFfyPotT2WpEI+GqimalTEu
         HJ4DSUf7xKTrf+7Va7Oh2XncvtKU/9+C7JJFOj0oCpPc2vfbT5enhptyACKvVwNlZTJB
         sWdTFriTYaOdL9v3QlWT8vbvT5lMupBx+kBC6vCX0zjr09v/SqfIKYsAngB48vReiPuN
         S9Z0qpixbYoljXchrSdDlr5YWrfYClBVnl3egG4EfWRXb4AxWWs/eupUswknkTLPWOwY
         Mpfw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=JB137Y60BhwWEDBjTqvHulcYwQ9jTNh9hWVkbeGFpbY=;
        fh=FiMl4UCKAIxccHtcdYqOll69jdkaDIp+NSebXbeeO2s=;
        b=cNRUshvzawE2g7WFkMoES9FxFdzevOQJ7LlZcRfVwE9a2hN8nZN0r6YEKJR4raaerB
         GoR4AhKcVbtuJZG3nJZdRqtABtXLlqctX/mAX9vXq9w2nArzZbzqNH6Wf6QfAfbfJ9P+
         kr/avkPDBFsrCb6MQwJ2PF2tvQw4a7wh2FQhxy6TGOsoZDb4w4Od8oxoGGMLTn6fWiJT
         lPjH0ZRou/hxEYjz/4j1E7SfoUF03zJ1hLX0OMxPoUFHcqVwY+rn5kjFHA6ddb7XTlK3
         G9XNxlJwA0XoEiOp2s5yH3Mem3AigLxipOf3DXa10PfPlrCoj3NBEG0H8i38NsHPu9xB
         4mgQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=qS+uN0R+;
       spf=pass (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::62a as permitted sender) smtp.mailfrom=nogikh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x62a.google.com (mail-pl1-x62a.google.com. [2607:f8b0:4864:20::62a])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-70476b1f1e1si324750b3a.1.2024.06.12.03.11.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 12 Jun 2024 03:11:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::62a as permitted sender) client-ip=2607:f8b0:4864:20::62a;
Received: by mail-pl1-x62a.google.com with SMTP id d9443c01a7336-1f61742a024so148205ad.0
        for <kasan-dev@googlegroups.com>; Wed, 12 Jun 2024 03:11:42 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVbfcrW2mhE0UkMfL5sZ66fMfqQVWBRNLz2uS1cu1IeCoTpzPRrj7MYHMiAQlLfSzemOfNo+ucEgdy/dR7anEmgw9aCe+LwusQUmg==
X-Received: by 2002:a17:902:c40a:b0:1e0:c571:d652 with SMTP id
 d9443c01a7336-1f83b371decmr2105695ad.1.1718187101848; Wed, 12 Jun 2024
 03:11:41 -0700 (PDT)
MIME-Version: 1.0
References: <20240611133229.527822-1-nogikh@google.com> <20240611115133.fa80466e924ad34ed4ad73cb@linux-foundation.org>
In-Reply-To: <20240611115133.fa80466e924ad34ed4ad73cb@linux-foundation.org>
From: "'Aleksandr Nogikh' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 12 Jun 2024 12:11:30 +0200
Message-ID: <CANp29Y6TqZ2T5xKzwW8RJ4o7+4w+mWs2awNebXo1dyaw154Opg@mail.gmail.com>
Subject: Re: [PATCH] kcov: don't lose track of remote references during softirqs
To: Andrew Morton <akpm@linux-foundation.org>
Cc: dvyukov@google.com, andreyknvl@gmail.com, arnd@arndb.de, elver@google.com, 
	glider@google.com, syzkaller@googlegroups.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: nogikh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=qS+uN0R+;       spf=pass
 (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::62a as
 permitted sender) smtp.mailfrom=nogikh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Tue, Jun 11, 2024 at 8:51=E2=80=AFPM Andrew Morton <akpm@linux-foundatio=
n.org> wrote:
>
> On Tue, 11 Jun 2024 15:32:29 +0200 Aleksandr Nogikh <nogikh@google.com> w=
rote:
>
> > In kcov_remote_start()/kcov_remote_stop(), we swap the previous KCOV
> > metadata of the current task into a per-CPU variable. However, the
> > kcov_mode_enabled(mode) check is not sufficient in the case of remote
> > KCOV coverage: current->kcov_mode always remains KCOV_MODE_DISABLED
> > for remote KCOV objects.
> >
> > If the original task that has invoked the KCOV_REMOTE_ENABLE ioctl
> > happens to get interrupted and kcov_remote_start() is called, it
> > ultimately leads to kcov_remote_stop() NOT restoring the original
> > KCOV reference. So when the task exits, all registered remote KCOV
> > handles remain active forever.
> >
> > Fix it by introducing a special kcov_mode that is assigned to the
> > task that owns a KCOV remote object. It makes kcov_mode_enabled()
> > return true and yet does not trigger coverage collection in
> > __sanitizer_cov_trace_pc() and write_comp_data().
>
> What are the userspace visible effects of this bug?  I *think* it's
> just an efficiency thing, but how significant?  In other words, should
> we backport this fix?
>

The most uncomfortable effect (at least for syzkaller) is that the bug
prevents the reuse of the same /sys/kernel/debug/kcov descriptor. If
we obtain it in the parent process and then e.g. drop some
capabilities and continuously fork to execute individual programs, at
some point current->kcov of the forked process is lost,
kcov_task_exit() takes no action, and all KCOV_REMOTE_ENABLE ioctls
calls from subsequent forks fail.

And, yes, the efficiency is also affected if we keep on losing remote
kcov objects.
a) kcov_remote_map keeps on growing forever.
b) (If I'm not mistaken), we're also not freeing the memory referenced
by kcov->area.

I think it would be nice to backport the fix to the stable trees.

--=20
Aleksandr

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANp29Y6TqZ2T5xKzwW8RJ4o7%2B4w%2BmWs2awNebXo1dyaw154Opg%40mail.gm=
ail.com.
