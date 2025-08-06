Return-Path: <kasan-dev+bncBCC4R3XF44KBBHGNZPCAMGQEPZC4Z4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id C6061B1BFDE
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Aug 2025 07:22:38 +0200 (CEST)
Received: by mail-qv1-xf3e.google.com with SMTP id 6a1803df08f44-70734e02839sf141170906d6.2
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Aug 2025 22:22:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754457757; cv=pass;
        d=google.com; s=arc-20240605;
        b=a51zlARkM98+kET8ZV+cXM+tIgUeKaLXyP3cOqfXc+FI69K8OxhzryAqLKV4Rv1VZU
         d9KrnfUrd6Juu4UNTMYXWIV/HXSKPknHHANn2XOt68IpbPJ44UuYlFvjoIkLXgdlpQjD
         XHCrUIP9e6htFE7/70NnN1vEZ3j6fYivZJFP0ZTBEgv+/4QDuOM9zG/h7PXGTt1MhOcs
         E7evImEcHQqml2BuzTy+hu4AK0LotQsHy05XnJ24020t+fVS4OX/xvxhoU7Pmd2bK4CV
         fEDhGD7SFOxKcP2xSOfETS/WF5bWtbi/ROvGTR13j0EOFK2NAyAL9QfMY/sLX4fvxihQ
         G6dA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=u468MOMVD/ZAp81b+1fht9eMnWErQ6ilxI3jvtuqxkc=;
        fh=yZBA+fd7QVOza31nFl8Wiz+8AUE/HkRz+tMjc+wc/xg=;
        b=MblkzG6lF9uL619BjC8MSYdWFI2x4BJzlXv0K6iug5cPzoHi3TYEYkVYBiM9+d0RzB
         saCKqWNjH49nqfuN29RoX+2bTtD6Ksl0X+DEgwyFiYdcLSP96o/+2k9u1AqDjW7TWT0j
         0mqE3uAp3jaH7ryAE/VGkfneYmU+QaVavcBQnDrtjHQ7vWRvxZ3eaqdA2xj3WvlZhUQ/
         6Dh7Wf5DZHM9cfF2tTNCXNq+lAKQ6AuBIJ4Cwq8DLCrbTGfkEbJ3H6pBVC8TtLFl4S3t
         Tybver+jA0eD0tIxGaBEkI+F7MzULSpGPJUsyJEdvdrHiFOSn4Qo9lJXJNkIvrDF8Jv5
         AuHg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=re4ea+rO;
       spf=pass (google.com: domain of sj@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=sj@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754457757; x=1755062557; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=u468MOMVD/ZAp81b+1fht9eMnWErQ6ilxI3jvtuqxkc=;
        b=w57NxzplWFrhaPuPgcmTnrbtKbyqbMuaZd09D6MrvMA6o2WvK2sWFP2HzRpkSYMyw4
         Pd0uS1TcjKO4tFneFWmsH5r+zEM3WEcSBpeFFY3Iraq+b0IejuA73EYeZXA/TcP2Dm3F
         Km4K5UAmMUbsp8o0KT126K5x4Iv/eczj7GgMDeRxowh7RPEY41z9XRoyMCrs8zrBxfcp
         AKd8/+HW+qTgKkWA66VNHLF1zRiQ47Dgduy3g7gOFvXsSfanUMOVzXbO7nqsTsDXDQpr
         8yyLBNzESejQalUTnD7v3NiLmQJ6kjlrv4ehjJR3WYKMnosoTvLzVcDjoqbrwB7HgoAq
         bYZw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754457757; x=1755062557;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=u468MOMVD/ZAp81b+1fht9eMnWErQ6ilxI3jvtuqxkc=;
        b=wEWVtUhtPTzjbPpIxF1W3zQpgS5gmoVnDOeh2fOCCwITr8UCgZQ4eUb+kpp/ECJwPp
         /B3JM+A/wCyQRKxvX4NjTHmXd0R8/aHpUlWEOXXECsluQTCX1PLtS6JNBMt3fsutoinG
         1Nc7Ug33BjxvX7s7lNbCjQ5rHC1QPOHef8V2hQqfAHuuCig033tDY8DPIUaK2V8Jf9QN
         YKuoByHlG0+FtpIoonWn9OzvQJVDJ+oMVai9530sdjEEqpoFyx8aYngJKqDRQlyOU7EP
         1wdVrYcrhyhpAodrdTobs5ZXF65rHhhNjBTuSApyMrID6Chk8EwMiz0Yj9xNThsbwnrb
         FX8Q==
X-Forwarded-Encrypted: i=2; AJvYcCXd/taKRXzFScJE7k9WJtFGZpKZBtNvsC2vdGTOotoX0dO/1+Oci0cSMW1CArHwOiJ6hNJKiw==@lfdr.de
X-Gm-Message-State: AOJu0YzDYUgRMz/U14a+Yp1x3LzjSNT3E4tpId79LBLfjtZPEr7nzi4q
	n+nlk9YLHgXXKhsnYL5H04/lcjyoc4lr6dzNpOonzOrCnN4/490G4Iqm
X-Google-Smtp-Source: AGHT+IHhySqtyIZJ7GNhb8CYTQVTtvprSGxHY7X2bzwIpmRB/j9tfffXtglY0X2TcGtSOCeyUleC8Q==
X-Received: by 2002:a05:6214:411e:b0:707:5df5:c719 with SMTP id 6a1803df08f44-70979525bd6mr25137376d6.17.1754457756926;
        Tue, 05 Aug 2025 22:22:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcSQofvAM8jnW9xcvbdQLCM4CZe72j3+oGLBlcLgDldRw==
Received: by 2002:a05:6214:76a:b0:706:c5eb:9c9e with SMTP id
 6a1803df08f44-70778d6404cls126287396d6.1.-pod-prod-04-us; Tue, 05 Aug 2025
 22:22:36 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX12tnW7Y689yvKSf9A4R9BjWDjkNDfLJtCANpaXdfRztdrcxUXg8BY+FTDuubmhov06LPoIx+0Lxc=@googlegroups.com
X-Received: by 2002:ad4:5bca:0:b0:704:95c6:f5f1 with SMTP id 6a1803df08f44-7097969fd4amr26652786d6.34.1754457755973;
        Tue, 05 Aug 2025 22:22:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754457755; cv=none;
        d=google.com; s=arc-20240605;
        b=e6UkZZZrcLbS1hJ0+N/EQ2LMsimMth+9d5mQKrINS3BYkTtVol06HbZ/YCOSk6Jfz8
         FsiK10RyYBXnuVEYMUbk+n44xSudpqQVSNj15+j6rlwQxhzciAutlZRLTLKHQ4PPdomf
         2foH1tl11t26D3WzLoKWJZegm3i1vOENc7qAJmCPwQGmDuOho1lXzCc7oUoMSDPxVqvc
         r0B3j3LcDcSr9ESAPj3IF5BrMeW3mlci6anTNoEWPX4AbpVCDE0A7o9eIKd0u7CAgvjM
         3rbcAIXAOAB5UrAZll7tiZOVL2tPYZTtbGyxUBFXc9db1TBz0y6V8fu7Nq5dmqStPkRl
         yu8w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=XjJbearcpYLygH3I9UtbiSxWfVYe30GcdnmkpjPEww4=;
        fh=4Ecr1l/hmhigpMtapn23TN0EzSydaoz0q4WGwZaekvU=;
        b=GbcHjqSixVaa8FhE45jIhEisELtbZS234Ds5TIcjbXA+tHeOgDBtORVJ/7CnRDwaVC
         rpT3eDiIGkaS1WQhaoNZvuP3/IwVVuFjyeiT+qeA5mfX6Lcy3q8r7Man/zAZ9Ye0bBkR
         4odRRD0HLy0FFcrLTrp67BZt6GyKi4T08HOX3VcNnJ3Yj+TThLBk+MMzDMNnuBWFwu9p
         jFkeFf/l3l+NmcfZdRLWvo66BQMYc0CHtp8/VIIDyrE9VnACDiAhWNhMXsnuSqEWvEuM
         4DgJOVCVRv20GXAJRJS0gZAn9m4DhM6lKXjYN4wgMKZL4GZ7I0zxFr1rOCA9oFKbEhyI
         Z2cQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=re4ea+rO;
       spf=pass (google.com: domain of sj@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=sj@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [2604:1380:45d1:ec00::3])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-7077c8c5c57si6517536d6.4.2025.08.05.22.22.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 05 Aug 2025 22:22:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of sj@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) client-ip=2604:1380:45d1:ec00::3;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 8733AA568C6;
	Wed,  6 Aug 2025 05:22:35 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A8FD0C4CEF6;
	Wed,  6 Aug 2025 05:22:34 +0000 (UTC)
From: "'SeongJae Park' via kasan-dev" <kasan-dev@googlegroups.com>
To: Baoquan He <bhe@redhat.com>
Cc: SeongJae Park <sj@kernel.org>,
	linux-mm@kvack.org,
	ryabinin.a.a@gmail.com,
	glider@google.com,
	andreyknvl@gmail.com,
	dvyukov@google.com,
	vincenzo.frascino@arm.com,
	akpm@linux-foundation.org,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	kexec@lists.infradead.org
Subject: Re: [PATCH 4/4] mm/kasan: make kasan=on|off take effect for all three modes
Date: Tue,  5 Aug 2025 22:22:31 -0700
Message-Id: <20250806052231.619715-1-sj@kernel.org>
X-Mailer: git-send-email 2.39.5
In-Reply-To: <20250805062333.121553-5-bhe@redhat.com>
References: 
MIME-Version: 1.0
X-Original-Sender: sj@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=re4ea+rO;       spf=pass
 (google.com: domain of sj@kernel.org designates 2604:1380:45d1:ec00::3 as
 permitted sender) smtp.mailfrom=sj@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: SeongJae Park <sj@kernel.org>
Reply-To: SeongJae Park <sj@kernel.org>
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

Hello Baoqua,

On Tue,  5 Aug 2025 14:23:33 +0800 Baoquan He <bhe@redhat.com> wrote:

> Now everything is ready, set kasan=off can disable kasan for all
> three modes.
> 
> Signed-off-by: Baoquan He <bhe@redhat.com>
> ---
>  include/linux/kasan-enabled.h | 11 +----------
>  1 file changed, 1 insertion(+), 10 deletions(-)
> 
> diff --git a/include/linux/kasan-enabled.h b/include/linux/kasan-enabled.h
> index 32f2d19f599f..b5857e15ef14 100644
> --- a/include/linux/kasan-enabled.h
> +++ b/include/linux/kasan-enabled.h
> @@ -8,30 +8,21 @@ extern bool kasan_arg_disabled;
>  
>  DECLARE_STATIC_KEY_FALSE(kasan_flag_enabled);
>  
> -#ifdef CONFIG_KASAN_HW_TAGS
> -
>  static __always_inline bool kasan_enabled(void)
>  {
>  	return static_branch_likely(&kasan_flag_enabled);
>  }

I found mm-new build fails when CONFIG_KASAN is unset as below, and 'git
bisect' points this patch.

      LD      .tmp_vmlinux1
    ld: lib/stackdepot.o:(__jump_table+0x8): undefined reference to `kasan_flag_enabled'

Since kasna_flag_enabled is defined in mm/kasan/common.c, I confirmed diff like
below fixes this.  I think it may not be a correct fix though, since I didn't
read this patchset thoroughly.

diff --git a/include/linux/kasan-enabled.h b/include/linux/kasan-enabled.h
index b5857e15ef14..a53d112b1020 100644
--- a/include/linux/kasan-enabled.h
+++ b/include/linux/kasan-enabled.h
@@ -8,11 +8,22 @@ extern bool kasan_arg_disabled;
 
 DECLARE_STATIC_KEY_FALSE(kasan_flag_enabled);
 
+#ifdef CONFIG_KASAN
+
 static __always_inline bool kasan_enabled(void)
 {
 	return static_branch_likely(&kasan_flag_enabled);
 }
 
+#else /* CONFIG_KASAN */
+
+static inline bool kasan_enabled(void)
+{
+	return false;
+}
+
+#endif
+
 #ifdef CONFIG_KASAN_HW_TAGS
 static inline bool kasan_hw_tags_enabled(void)
 {


[...]

Thanks,
SJ

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250806052231.619715-1-sj%40kernel.org.
