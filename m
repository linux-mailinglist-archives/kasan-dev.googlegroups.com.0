Return-Path: <kasan-dev+bncBCUJ7YGL3QFBBFP56KPAMGQEOFE2FOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id 5EFB168915C
	for <lists+kasan-dev@lfdr.de>; Fri,  3 Feb 2023 08:58:14 +0100 (CET)
Received: by mail-qt1-x83b.google.com with SMTP id p6-20020a05622a048600b003b9a3ab9153sf2246332qtx.8
        for <lists+kasan-dev@lfdr.de>; Thu, 02 Feb 2023 23:58:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675411093; cv=pass;
        d=google.com; s=arc-20160816;
        b=cwLc6dBROxAZOQ/QnPmml8RIf1wBBor/7ZXHoHr47npeuyruG/vCWdBcuYBM75a/Ux
         Qu35xhz8z2YlZfmMe1DJb5/ER/Mr2b+2rx54Y3MxD/bgnJIfcZFpRou+wAZqGyXNbmrr
         CfBGyGXoYT7raa5QYNOndXnK9rpyWJHwki/uKFAUJT0r6pKnvPd7zYo1Hl+7VbJkz5Ok
         rx7Twi4CHn/ZjDAuVoRQQ0uwKuhLRHbt+/hGZ98/HeSsb1TlOHLWa+If8y8+P+q6ZWem
         tFOwTtB0wrOUAslNjAdmr5WFa/DzRWYOSTGdlS/fjKbLNk/0P3PJtGg+4RkWQLvaOPS3
         Y4mA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:in-reply-to:date:from:cc:to:subject:sender
         :dkim-signature;
        bh=/USGSkK323PbqtAErv+fw0m+e0iECrZBohKGHpkBHaI=;
        b=nKr4rsTB6ROQYuBm50xyrIHJVFUoaLOvLi+IljqQIZ87YTkmQ/gX3bJKj9Ajghmec5
         vB1+twAALAVIjakQqh3B2+8cUyaYPkEBVl57yUZkURRdCn8KWnks04B8ngtjm+GMeG7s
         EazC3D4/fRKBgC2IVv54bxCroRKgklBBq3LxqWxIExt9C4kSUt/PBgyCOENIy2JCnDi4
         ANWBaeempLgDQi0q9Urb1Ql/yNmMzSowX061XY5ZdDUiPozD9OQRLi0A3tb2/BoGf38Z
         eGgT6vUpiXlGXP9IvmvBfDcl4KudEy85nWR55tAOyF21vTNZ0wkO+t3dN7r758MICLxJ
         FlzA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=neutral (body hash did not verify) header.i=@linuxfoundation.org header.s=korg header.b=Cm05RmJt;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:message-id
         :in-reply-to:date:from:cc:to:subject:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=/USGSkK323PbqtAErv+fw0m+e0iECrZBohKGHpkBHaI=;
        b=nL/+ohJ+Wcr2oaDXRLYk93n6kkFHAwnUq0Nbp7YDaK8tLFJh638JK/YNocU1t9t5SD
         eHW6wOH1rouMPyuQrw3WGjalXT9aWI32DWLqEpvvL/bTAu1SML1mwH9zh6+44/79KGGV
         MVfqsel4Edsxw2Cofi9SF4xj8IpSx93LR2s+b4Y3T0Tk725ncuIHPHrlPbrxC5dSxTv8
         Hv4So1MD5fEZcEx0qY5Ut//job6seCUjU3Ki7w4v9sKozgg2FtK9kmZvB8Ft5w1g8ptr
         motgHAetHO4xQMEnNb5hzoF9+4iyqzphw/ldmHo4l2CaAi2yqA/XvQcL6jEjG2K3Zisy
         16Lg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:message-id:in-reply-to:date
         :from:cc:to:subject:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=/USGSkK323PbqtAErv+fw0m+e0iECrZBohKGHpkBHaI=;
        b=77QuQGkIacizGZ/vpwrmNqQpHX9+asCcoE4sFMgO3x55ESIrB3J+1WdICDVrs42dIz
         Aehy0ubTosmquMi+gP6FTWr1dsxki7DA/ZNL/VjuepUSdSH7VxKVVXqwb3Pea7LMhZWI
         ktc/Gjsk3ToSFvg9ya6Pvnm3yzx6hSPbX6q2ek4Q7cXDjglyGBe2xZipBw+/swqyxp8b
         5hv/RtFVmFf98jIb5aJ8IRvuZDLEu75IKyZ4swIl304JzPMw5EBOK2TMfY5FH+4r46Vb
         qyccDogJboNuZVnxThX+K/XBHeSjQdM1JGgLTW5iHGeWj88deBzEt37Cm4iukuwuz7fy
         KNsQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKXscJjt2m7AR1XddDIAj93SNVH68O2ph5dE3NjyPFD2NQmreENL
	QtIenOnlQQB4OG72w1CFKf8=
X-Google-Smtp-Source: AK7set8aUSUEOqPUnzMbK2/g3gS9Yu8z95Ubh6avvhfmKR4xJgMtr6b4n08pi3yCQuMCr0kXNIQ69w==
X-Received: by 2002:a05:622a:5d3:b0:3b9:b74a:8dd3 with SMTP id d19-20020a05622a05d300b003b9b74a8dd3mr1113287qtb.188.1675411093131;
        Thu, 02 Feb 2023 23:58:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:2446:b0:3b7:ea5e:962f with SMTP id
 bl6-20020a05622a244600b003b7ea5e962fls4530042qtb.6.-pod-prod-gmail; Thu, 02
 Feb 2023 23:58:12 -0800 (PST)
X-Received: by 2002:a05:622a:130e:b0:3b3:7707:9b92 with SMTP id v14-20020a05622a130e00b003b377079b92mr18587132qtk.15.1675411092566;
        Thu, 02 Feb 2023 23:58:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675411092; cv=none;
        d=google.com; s=arc-20160816;
        b=w0AmTYpMaNesVZ+ibK6CGyi5wG5xrTZvGBIZhSjAkd74/3/1bBsUePGd7SAOgeaigZ
         4otJItMvtIavGa+oc0wIzob+qKJm44DskvMHuZhkbVSDNTnu4kmB20ILh1R/vGhR3rJW
         Qs0Wk622bwh14vAMGf2h73KSYUHh1oKL1Pvz3dW8Drn89emEQFRtws1GkLYjFGNUnqQS
         X4ncIprOJDeQPjAXTn8UN/2By8M/2R556bvXw6WGcdiaudoXwhvZBkZoh5OgDXeW53FV
         o9u/EaRuiE3pUeR06PZ+lnVx/usMmgpknyS+MJyM/9f6I3GKrPLr0ikRLIZTRH1C0j0+
         hZPA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:in-reply-to:date
         :from:cc:to:subject:dkim-signature;
        bh=K5Uq4cn+bz52/cQoFVa4zeT/J9tBHQs6Ad75I8R2w/M=;
        b=es3akJbxYN3emDY5626DN+4wWTxiNVpjCgNvywSTAfUOeSwnsW7auBDslnx6W++rJe
         Kiw6aksGhtKv7yL6WnipeS/Z8YE5MFyC/oQmrk5BtE6v766AOREejcGDtgB2BXLCz51w
         PafFzC49+yKmYqrUEC6r3jOpv/fLxBMjf5J9vqG16+9oebjec8T+/afRGqn7QObXZhsW
         Xu4kRfHdYij+NhTqqVHsft2/mGil2FhotMTcvgRHvCKRP/Sd6QdiJGPeHRJ0qHfpzRO/
         3DyEINvuXDLqOKzcIfHG3DfgrZyE5pRtbaaO4vlokyabBURRxhMltekYGmGzDarSIz0h
         x68g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=neutral (body hash did not verify) header.i=@linuxfoundation.org header.s=korg header.b=Cm05RmJt;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id i11-20020a05620a404b00b0072ceb3a9fe4si127382qko.6.2023.02.02.23.58.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 02 Feb 2023 23:58:12 -0800 (PST)
Received-SPF: pass (google.com: domain of gregkh@linuxfoundation.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 1070E61E12;
	Fri,  3 Feb 2023 07:58:12 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id CF513C433D2;
	Fri,  3 Feb 2023 07:58:10 +0000 (UTC)
Subject: Patch "panic: Consolidate open-coded panic_on_warn checks" has been added to the 4.14-stable tree
To: akpm@linux-foundation.org,andreyknvl@gmail.com,bigeasy@linutronix.de,bristot@redhat.com,bsegall@google.com,davidgow@google.com,dietmar.eggemann@arm.com,dvyukov@google.com,ebiederm@xmission.com,ebiggers@google.com,ebiggers@kernel.org,elver@google.com,glider@google.com,gpiccoli@igalia.com,gregkh@linuxfoundation.org,harshit.m.mogalapalli@oracle.com,jannh@google.com,juri.lelli@redhat.com,kasan-dev@googlegroups.com,keescook@chromium.org,linux-mm@kvack.org,mcgrof@kernel.org,mgorman@suse.de,mingo@redhat.com,paulmck@kernel.org,peterz@infradead.org,pmladek@suse.com,rostedt@goodmis.org,ryabinin.a.a@gmail.com,sethjenkins@google.com,sj@kernel.org,skhan@linuxfoundation.org,tangmeng@uniontech.com,vincent.guittot@linaro.org,vincenzo.frascino@arm.com,vschneid@redhat.com,yangtiezhu@loongson.cn
Cc: <stable-commits@vger.kernel.org>
From: <gregkh@linuxfoundation.org>
Date: Fri, 03 Feb 2023 08:57:36 +0100
In-Reply-To: <20230203003354.85691-12-ebiggers@kernel.org>
Message-ID: <1675411056117153@kroah.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-stable: commit
X-Patchwork-Hint: ignore
X-Original-Sender: gregkh@linuxfoundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=neutral (body
 hash did not verify) header.i=@linuxfoundation.org header.s=korg
 header.b=Cm05RmJt;       spf=pass (google.com: domain of gregkh@linuxfoundation.org
 designates 139.178.84.217 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
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


This is a note to let you know that I've just added the patch titled

    panic: Consolidate open-coded panic_on_warn checks

to the 4.14-stable tree which can be found at:
    http://www.kernel.org/git/?p=3Dlinux/kernel/git/stable/stable-queue.git=
;a=3Dsummary

The filename of the patch is:
     panic-consolidate-open-coded-panic_on_warn-checks.patch
and it can be found in the queue-4.14 subdirectory.

If you, or anyone else, feels it should not be added to the stable tree,
please let <stable@vger.kernel.org> know about it.


From stable-owner@vger.kernel.org Fri Feb  3 01:35:49 2023
From: Eric Biggers <ebiggers@kernel.org>
Date: Thu,  2 Feb 2023 16:33:50 -0800
Subject: panic: Consolidate open-coded panic_on_warn checks
To: stable@vger.kernel.org
Cc: Harshit Mogalapalli <harshit.m.mogalapalli@oracle.com>, Kees Cook <kees=
cook@chromium.org>, SeongJae Park <sj@kernel.org>, Seth Jenkins <sethjenkin=
s@google.com>, Jann Horn <jannh@google.com>, "Eric W . Biederman" <ebiederm=
@xmission.com>, linux-hardening@vger.kernel.org, linux-kernel@vger.kernel.o=
rg, Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, Ing=
o Molnar <mingo@redhat.com>, Peter Zijlstra <peterz@infradead.org>, Juri Le=
lli <juri.lelli@redhat.com>, Vincent Guittot <vincent.guittot@linaro.org>, =
Dietmar Eggemann <dietmar.eggemann@arm.com>, Steven Rostedt <rostedt@goodmi=
s.org>, Ben Segall <bsegall@google.com>, Mel Gorman <mgorman@suse.de>, Dani=
el Bristot de Oliveira <bristot@redhat.com>, Valentin Schneider <vschneid@r=
edhat.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <=
glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Vincenzo Frasc=
ino <vincenzo.frascino@arm.com>, Andrew Morton <akpm@linux-foundation.org>,=
 David Gow <davidgow@go
 ogle.com>, tangmeng <tangmeng@uniontech.com>, Shuah Khan <skhan@linuxfound=
ation.org>, Petr Mladek <pmladek@suse.com>, "Paul E. McKenney" <paulmck@ker=
nel.org>, Sebastian Andrzej Siewior <bigeasy@linutronix.de>, "Guilherme G. =
Piccoli" <gpiccoli@igalia.com>, Tiezhu Yang <yangtiezhu@loongson.cn>, kasan=
-dev@googlegroups.com, linux-mm@kvack.org, Luis Chamberlain <mcgrof@kernel.=
org>
Message-ID: <20230203003354.85691-12-ebiggers@kernel.org>

From: Kees Cook <keescook@chromium.org>

commit 79cc1ba7badf9e7a12af99695a557e9ce27ee967 upstream.

Several run-time checkers (KASAN, UBSAN, KFENCE, KCSAN, sched) roll
their own warnings, and each check "panic_on_warn". Consolidate this
into a single function so that future instrumentation can be added in
a single location.

Cc: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Ingo Molnar <mingo@redhat.com>
Cc: Peter Zijlstra <peterz@infradead.org>
Cc: Juri Lelli <juri.lelli@redhat.com>
Cc: Vincent Guittot <vincent.guittot@linaro.org>
Cc: Dietmar Eggemann <dietmar.eggemann@arm.com>
Cc: Steven Rostedt <rostedt@goodmis.org>
Cc: Ben Segall <bsegall@google.com>
Cc: Mel Gorman <mgorman@suse.de>
Cc: Daniel Bristot de Oliveira <bristot@redhat.com>
Cc: Valentin Schneider <vschneid@redhat.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Andrew Morton <akpm@linux-foundation.org>
Cc: David Gow <davidgow@google.com>
Cc: tangmeng <tangmeng@uniontech.com>
Cc: Jann Horn <jannh@google.com>
Cc: Shuah Khan <skhan@linuxfoundation.org>
Cc: Petr Mladek <pmladek@suse.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Cc: "Guilherme G. Piccoli" <gpiccoli@igalia.com>
Cc: Tiezhu Yang <yangtiezhu@loongson.cn>
Cc: kasan-dev@googlegroups.com
Cc: linux-mm@kvack.org
Reviewed-by: Luis Chamberlain <mcgrof@kernel.org>
Signed-off-by: Kees Cook <keescook@chromium.org>
Reviewed-by: Marco Elver <elver@google.com>
Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
Link: https://lore.kernel.org/r/20221117234328.594699-4-keescook@chromium.o=
rg
Signed-off-by: Eric Biggers <ebiggers@google.com>
Signed-off-by: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
---
 include/linux/kernel.h |    1 +
 kernel/panic.c         |    9 +++++++--
 kernel/sched/core.c    |    3 +--
 mm/kasan/report.c      |    3 +--
 4 files changed, 10 insertions(+), 6 deletions(-)

--- a/include/linux/kernel.h
+++ b/include/linux/kernel.h
@@ -293,6 +293,7 @@ extern long (*panic_blink)(int state);
 __printf(1, 2)
 void panic(const char *fmt, ...) __noreturn __cold;
 void nmi_panic(struct pt_regs *regs, const char *msg);
+void check_panic_on_warn(const char *origin);
 extern void oops_enter(void);
 extern void oops_exit(void);
 void print_oops_end_marker(void);
--- a/kernel/panic.c
+++ b/kernel/panic.c
@@ -122,6 +122,12 @@ void nmi_panic(struct pt_regs *regs, con
 }
 EXPORT_SYMBOL(nmi_panic);
=20
+void check_panic_on_warn(const char *origin)
+{
+	if (panic_on_warn)
+		panic("%s: panic_on_warn set ...\n", origin);
+}
+
 /**
  *	panic - halt the system
  *	@fmt: The text string to print
@@ -546,8 +552,7 @@ void __warn(const char *file, int line,
 	if (args)
 		vprintk(args->fmt, args->args);
=20
-	if (panic_on_warn)
-		panic("panic_on_warn set ...\n");
+	check_panic_on_warn("kernel");
=20
 	print_modules();
=20
--- a/kernel/sched/core.c
+++ b/kernel/sched/core.c
@@ -3185,8 +3185,7 @@ static noinline void __schedule_bug(stru
 		print_ip_sym(preempt_disable_ip);
 		pr_cont("\n");
 	}
-	if (panic_on_warn)
-		panic("scheduling while atomic\n");
+	check_panic_on_warn("scheduling while atomic");
=20
 	dump_stack();
 	add_taint(TAINT_WARN, LOCKDEP_STILL_OK);
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -172,8 +172,7 @@ static void kasan_end_report(unsigned lo
 	pr_err("=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D\n");
 	add_taint(TAINT_BAD_PAGE, LOCKDEP_NOW_UNRELIABLE);
 	spin_unlock_irqrestore(&report_lock, *flags);
-	if (panic_on_warn)
-		panic("panic_on_warn set ...\n");
+	check_panic_on_warn("KASAN");
 	kasan_enable_current();
 }
=20


Patches currently in stable-queue which might be from stable-owner@vger.ker=
nel.org are

queue-4.14/panic-unset-panic_on_warn-inside-panic.patch
queue-4.14/objtool-add-a-missing-comma-to-avoid-string-concatenation.patch
queue-4.14/hexagon-fix-function-name-in-die.patch
queue-4.14/exit-add-and-use-make_task_dead.patch
queue-4.14/h8300-fix-build-errors-from-do_exit-to-make_task_dead-transition=
.patch
queue-4.14/panic-consolidate-open-coded-panic_on_warn-checks.patch
queue-4.14/exit-put-an-upper-limit-on-how-often-we-can-oops.patch
queue-4.14/panic-introduce-warn_limit.patch
queue-4.14/exit-allow-oops_limit-to-be-disabled.patch
queue-4.14/ia64-make-ia64_mca_recovery-bool-instead-of-tristate.patch
queue-4.14/exit-use-read_once-for-all-oops-warn-limit-reads.patch
queue-4.14/exit-expose-oops_count-to-sysfs.patch
queue-4.14/panic-expose-warn_count-to-sysfs.patch
queue-4.14/docs-fix-path-paste-o-for-sys-kernel-warn_count.patch
queue-4.14/sysctl-add-a-new-register_sysctl_init-interface.patch

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/1675411056117153%40kroah.com.
