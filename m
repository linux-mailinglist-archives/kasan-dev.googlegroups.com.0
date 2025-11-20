Return-Path: <kasan-dev+bncBC7OBJGL2MHBB7677TEAMGQETW6R5JI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 3D79AC74C57
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Nov 2025 16:13:05 +0100 (CET)
Received: by mail-lj1-x237.google.com with SMTP id 38308e7fff4ca-37a2d8cc3d3sf9798501fa.0
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Nov 2025 07:13:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1763651584; cv=pass;
        d=google.com; s=arc-20240605;
        b=HVK3zF+Iabrj903SAAhueLW2b0cHkIAAzbbdoOq4nOL2T9nkkF+5DpHKeHafLtjoEq
         eiZzohCrrdjtvNCzehLq2iGycN9Weiz5+fdsk43sGAa2O1r3EQVlUyN6O6Q9F731ekBi
         epCC2qVsOVJZMwgYce12Y1qYsPMH1/A0onzGGlEAR0xyKpBk/3dW2hGpbnrvJqYbmvi4
         /sTu4XQvhSXR8WIrUAn8pWWsJURD6lUpLAFFkL6+tY6O2Mj/kQX5DnK2dCfMbLHtJ/e9
         bgOvyFG1xtMA8QI/CZAA30TkQX8Ca4RDBqRVt7PlNp0sWvtN7I5aw1txBVVY+Ewpc8Rh
         ZAuw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=qZ/gjHhkj1GukQUwH3RNugkyqYYqZMx4TDLDhD9JXpI=;
        fh=/DEcg2m+IqnI6AqcQoHOglU2jVeR9v/OBTlsPOCuaxU=;
        b=AtP4Bbcg9BwsiovdNoV/MYMqvn4iWgJje4Lbbom3tomGv/Vu+pp9oGKA1tmuEF1Dl2
         nMpHB2jBQSdmDTOzu1ybnQ7IGkQbtxInwNeG0vY+t8Zn+g3G5GJg/nOJ1O5rZ37GgK5D
         yii4zOgWLS6r0c4LNE+7rZmyZZucOias+O3Qn1fCmQ0SdhnW7PHt3jdWOYUlyF4zrZ++
         0OoCqTCVnswP8Mw+FeIrhMSmQBaaI1cneNsOBJpTHZuUMU61DYAdF6D9vmxEyVS2J8eF
         9yLuBGx38u53ydKLuSl2XDZlycmJ5I2VYU8EsmcXjbbSEQSZEp3yA0HIh4TQZS0NQqQ6
         xVUQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=LK45nmkd;
       spf=pass (google.com: domain of 3_c8faqukcskjqajwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3_C8faQUKCSkJQaJWLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1763651584; x=1764256384; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:from:subject:message-id:references
         :mime-version:in-reply-to:date:from:to:cc:subject:date:message-id
         :reply-to;
        bh=qZ/gjHhkj1GukQUwH3RNugkyqYYqZMx4TDLDhD9JXpI=;
        b=JhOnp8AchVIVa7tUijp4OkKeVlEWqaEcdUTp2afKHKwmAyPHiodZvp+fE4JgWd/ZKY
         v6PouQAtQa7/O69EKjXQ79RbtTZBRG1DsH7yiZMfZ7Fi8tc0Ds0uTeNgcICdvsEN2y8W
         yP2MdZNGUlQ7wd2cFYbRQ5zZ7UGrgNHy8X7aH9eNpeHHHkRKx52TDyHJdKGtbiyVNJuQ
         gPQXhxsAxnPvWJsnoEc2yV6R9Hbyr4Q1gsUjttXqtJYJjQK9OvaeR8E2HHE+BrV+5t9L
         0Zqe5RATayGQJm7Z3jEcLMab5+Rujr0oHVPlws2sginXI3W3n3PwVQvYNgkXwflboJEa
         rHIg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1763651584; x=1764256384;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:from:subject:message-id:references
         :mime-version:in-reply-to:date:x-beenthere:x-gm-message-state:from
         :to:cc:subject:date:message-id:reply-to;
        bh=qZ/gjHhkj1GukQUwH3RNugkyqYYqZMx4TDLDhD9JXpI=;
        b=Ih4J5hLWKKUjuuWHgvyz8J1IGp2IIWSdSs2cOdAmGJRd2OBmulz3MakyzhAhFC0LQs
         eosaQ32kBAWrC3gi+4ahg8OfVRlpw/5x8eJ5j0yh2J1OhjS/b86jj5IK6H/lUCtv+VBI
         uU8csa8wrppNufgVZRmVnKO7TkW2MVygtQN2gwmPxqodnu4ZLRTIMSmn/6RCFbuOZukB
         5/1Yh3f3i3j9dX20Wp0ei4Qti1A6TU4ZfNliWGLzBTTbltEUrRiAyPW+iQyIhGVDJ/rj
         h8l3b6hZvtW9l8nd4vjZvmn6Mc7+j+USRObXEBqVQ7UtVhqqkmc9nak5H2MMZiJ1MWFR
         KXIw==
X-Forwarded-Encrypted: i=2; AJvYcCXyDeg2NQn1BohKt4E6zyoiB5bWFOtPAto0uiAlrIvNqeB5ye1kLS0aT6HH/RCwwReeUUudpQ==@lfdr.de
X-Gm-Message-State: AOJu0YziDgzsn+Mhq4L6jilFia9uCMMFaI+fLuVOAgC2K55W3aPt9+z8
	6vdd/0yFvd2zBolE7SHFuQQWPXSytrtUyDw34iwj7poGsQOvnmgQUVJw
X-Google-Smtp-Source: AGHT+IE+Ui9wrOycAfyl/g3BAnugsX7Pp+mkMYURDWrFRXJ0zJDEJzq0UcxebiGO3DoZJUTeWqs7CQ==
X-Received: by 2002:a05:6512:acf:b0:595:9d54:93e2 with SMTP id 2adb3069b0e04-5969ea3af86mr1061341e87.24.1763651584326;
        Thu, 20 Nov 2025 07:13:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+YzXwDphufz+d8BLFOXoOeBIeqobv9D0IaXZjlE62EAvA=="
Received: by 2002:a05:6512:800d:10b0:595:77b7:5e39 with SMTP id
 2adb3069b0e04-5959dc3c8f8ls143912e87.0.-pod-prod-00-eu-canary; Thu, 20 Nov
 2025 07:13:01 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCW5wAnJAyPo4XlGNUAY0kaVza3jnkIPpSuOkRk44kjlyrmR38gPltWWIMCfSgBrlIdsjL7hPy/3b6E=@googlegroups.com
X-Received: by 2002:a05:6512:ea9:b0:594:524d:d966 with SMTP id 2adb3069b0e04-5969ea298c3mr1112655e87.21.1763651581151;
        Thu, 20 Nov 2025 07:13:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1763651581; cv=none;
        d=google.com; s=arc-20240605;
        b=f6LCWmpn7PJ46lKEdcMLOt0MFJWYcwNU8xwb2tyHiMRKKGq1qFCa+KdsvT0XU/Qce4
         0sMCzpGoO61jUcsZf9706hnGM0wSVBd8tuZQwJ17bWGM5J57ff3LROmofgV9ESgwmp1v
         hRjEUk6ir9yM9yiNnEtPYfFwwLGixD1dXjD20+cw6dR0ZUGEBMdtp8ybtJli41ZNfTk/
         DPuYaxSypCNOwKQiiKEuBMTxFiYUS/Wgwni8Tdpu+ub+vbFxq28I08oX4MpzoBLX0WC5
         PxUZQIr/zpe6b8YRivobC/TayurPERmaNzi72xjirGeDmbt/Aa0xHCIQZ9NSen1Q97IG
         E2Ug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:from:subject:message-id:references
         :mime-version:in-reply-to:date:dkim-signature;
        bh=LTo30xRtk3dNAYk+WcMlGzrXIDi8Fd3AcvMY0oMy4/o=;
        fh=RWEnZCHSD6vEFZX32OkkFYKdn/+dbtrOT26NRNfXoWM=;
        b=G2y5NFbNv2YDTEwMTOgxT2Tvv+nVq77HmXTJy9C0RlxL05FcWi+F2pTzZ/EMVJXcfr
         nne4jT5wRHr41RDrw0lNtCWwkhd6EZhwA8fnVCMCLyTl8pWDeVPuUkP+ruFdMZXZMxb3
         S46x8iJ6FSYxiDw3QD6wTlrohmerCgzOnHValhJancLD/fzCnN1BOVrkA/c59Ojw/rWA
         eiDnY3bE9htdEbQHgI7ldGRXy2kpjTiL+62x2FBBUlcuB/TiN6gcOY4UmVjGC0yiCUSy
         tM+CKHhbZOqee2CIuQ60kS0pGg1BC1KR/TO+WGZwXAwthA4WywbyrENMTfx7fmLdVyT3
         xAOA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=LK45nmkd;
       spf=pass (google.com: domain of 3_c8faqukcskjqajwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3_C8faQUKCSkJQaJWLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-5969db7d6desi41693e87.1.2025.11.20.07.13.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 20 Nov 2025 07:13:01 -0800 (PST)
Received-SPF: pass (google.com: domain of 3_c8faqukcskjqajwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id 5b1f17b1804b1-4779393221aso5900825e9.2
        for <kasan-dev@googlegroups.com>; Thu, 20 Nov 2025 07:13:01 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXFP0mrypYDj/zmVIUNeLCtR1iFCQY2dq9XIKGY5rBgfMexMtgcdLmubYDlKrMlNidTB7RQKxpZ1ng=@googlegroups.com
X-Received: from wmqo14.prod.google.com ([2002:a05:600c:4fce:b0:46e:1e57:dbd6])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:600c:4ec6:b0:46e:32dd:1b1a
 with SMTP id 5b1f17b1804b1-477babc1fcfmr26767175e9.7.1763651580311; Thu, 20
 Nov 2025 07:13:00 -0800 (PST)
Date: Thu, 20 Nov 2025 16:09:43 +0100
In-Reply-To: <20251120151033.3840508-7-elver@google.com>
Mime-Version: 1.0
References: <20251120145835.3833031-2-elver@google.com> <20251120151033.3840508-7-elver@google.com>
X-Mailer: git-send-email 2.52.0.rc1.455.g30608eb744-goog
Message-ID: <20251120151033.3840508-19-elver@google.com>
Subject: [PATCH v4 18/35] locking/local_lock: Include missing headers
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>, 
	Boqun Feng <boqun.feng@gmail.com>, Ingo Molnar <mingo@kernel.org>, Will Deacon <will@kernel.org>
Cc: "David S. Miller" <davem@davemloft.net>, Luc Van Oostenryck <luc.vanoostenryck@gmail.com>, 
	Chris Li <sparse@chrisli.org>, "Paul E. McKenney" <paulmck@kernel.org>, 
	Alexander Potapenko <glider@google.com>, Arnd Bergmann <arnd@arndb.de>, Bart Van Assche <bvanassche@acm.org>, 
	Christoph Hellwig <hch@lst.de>, Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Frederic Weisbecker <frederic@kernel.org>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ian Rogers <irogers@google.com>, 
	Jann Horn <jannh@google.com>, Joel Fernandes <joelagnelf@nvidia.com>, 
	Johannes Berg <johannes.berg@intel.com>, Jonathan Corbet <corbet@lwn.net>, 
	Josh Triplett <josh@joshtriplett.org>, Justin Stitt <justinstitt@google.com>, 
	Kees Cook <kees@kernel.org>, Kentaro Takeda <takedakn@nttdata.co.jp>, 
	Lukas Bulwahn <lukas.bulwahn@gmail.com>, Mark Rutland <mark.rutland@arm.com>, 
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, Miguel Ojeda <ojeda@kernel.org>, 
	Nathan Chancellor <nathan@kernel.org>, Neeraj Upadhyay <neeraj.upadhyay@kernel.org>, 
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, Steven Rostedt <rostedt@goodmis.org>, 
	Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>, Thomas Gleixner <tglx@linutronix.de>, 
	Thomas Graf <tgraf@suug.ch>, Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>, 
	kasan-dev@googlegroups.com, linux-crypto@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	linux-security-module@vger.kernel.org, linux-sparse@vger.kernel.org, 
	linux-wireless@vger.kernel.org, llvm@lists.linux.dev, rcu@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=LK45nmkd;       spf=pass
 (google.com: domain of 3_c8faqukcskjqajwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3_C8faQUKCSkJQaJWLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
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

Including <linux/local_lock.h> into an empty TU will result in the
compiler complaining:

./include/linux/local_lock.h: In function =E2=80=98class_local_lock_irqsave=
_constructor=E2=80=99:
./include/linux/local_lock_internal.h:95:17: error: implicit declaration of=
 function =E2=80=98local_irq_save=E2=80=99; <...>
   95 |                 local_irq_save(flags);                          \
      |                 ^~~~~~~~~~~~~~

As well as (some architectures only, such as 'sh'):

./include/linux/local_lock_internal.h: In function =E2=80=98local_lock_acqu=
ire=E2=80=99:
./include/linux/local_lock_internal.h:33:20: error: =E2=80=98current=E2=80=
=99 undeclared (first use in this function)
   33 |         l->owner =3D current;

Include missing headers to allow including local_lock.h where the
required headers are not otherwise included.

Signed-off-by: Marco Elver <elver@google.com>
---
 include/linux/local_lock_internal.h | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/include/linux/local_lock_internal.h b/include/linux/local_lock=
_internal.h
index a4dc479157b5..9f6cb32f04b0 100644
--- a/include/linux/local_lock_internal.h
+++ b/include/linux/local_lock_internal.h
@@ -4,7 +4,9 @@
 #endif
=20
 #include <linux/percpu-defs.h>
+#include <linux/irqflags.h>
 #include <linux/lockdep.h>
+#include <asm/current.h>
=20
 #ifndef CONFIG_PREEMPT_RT
=20
--=20
2.52.0.rc1.455.g30608eb744-goog

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
0251120151033.3840508-19-elver%40google.com.
