Return-Path: <kasan-dev+bncBC7OBJGL2MHBBHMWV2XQMGQEATX7T4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 03C1F876CA4
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Mar 2024 23:03:11 +0100 (CET)
Received: by mail-pl1-x63e.google.com with SMTP id d9443c01a7336-1dd62ea9be4sf64175ad.1
        for <lists+kasan-dev@lfdr.de>; Fri, 08 Mar 2024 14:03:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1709935389; cv=pass;
        d=google.com; s=arc-20160816;
        b=WQ0xfgBma3xUwKfWL6C1FFeAog7Uoqiec22neXxxtSM+ystlHMKDpC3wombcLEnQpT
         UNWgeDAQ8W0Szu0vZi74cbbcYVd+zld8SWcXIuhR7bRfTwI6RMqNDqe2G0E652DyW6wS
         z4FK6VssdIfEf2ZQ/LmthpQ6KzXZ+8081lOQfs0jefpTp53Mlyr+STZ93HSXwVksMd2m
         RFXIVcNWQPs97HjHznyhFNJjrwK9CbvOiUrEc2c5gWjHWXCDJHNxNT1XB/ZhMQgyfN7z
         R64SOqraeHuelvnjPiyzG7rcx1u0+yLHr5VZkDIY/FD6R3YHXzFWdKnv14Hy6B7J/P7t
         0HYw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=GG10uVfrxxhkT0zeNzC2jkcOo+aOgfVZquqGbOZ5l04=;
        fh=f43+UgyHdVrkZ1Am/0M0QFP4xGv5pWUIwTIZmd3A54s=;
        b=wvitF4QC3SLE/K/nBzcap8iTBf1yeq6L65iZP3Z9HXJCyyZsNHKnHieq4G1x5lbvl5
         BRk66EcDyxdPRnHmT9LySC1tiUYtszOoXvI5XDoxbw1kfVEPSzNd2LNZUs1hN5dWsgYY
         TnpiWvzqMPDLKS/oEBuheCgfnz2qzsUWXTDn6nHf1c6FGqgPnNL7Iaz1kfbL1EeFQEqt
         Q1yTiKfomtTAtu5GIFlnlmLpLrGqvayaklc4ktTmw5xB2WrZASmITUjL0Xv6YyOjukXp
         gA9YB+qN8zbv+N3hKlcfuysjztgf1EPcWj+rKyCY1BjZeL35uhoacnrs72EGsR5oQ6Wz
         9laQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="Iu/zdOS+";
       spf=pass (google.com: domain of elver@google.com designates 2001:4860:4864:20::35 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1709935389; x=1710540189; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=GG10uVfrxxhkT0zeNzC2jkcOo+aOgfVZquqGbOZ5l04=;
        b=g22SLgwEDTnux2kv1pcIlmQC61XMJnhjEypDSa1pN8WR+r0LOG3nCi+V5b3MC6S18h
         p2rUvpEiZPPYnArkXfE7YyAqQjAQPyJyZZtJEUXfhCi4O5cxVWExBlGta1dmjGpESkzf
         Y9eMrRxU3EOHQaARdUSpCfcUJUc+pbfmEP5D/l8rU46UQZce0qn7hMqu/KSlkemuOCDz
         Gzaln2yXyf9nWePaARmBTDHoSLBeu79ci3zAkqpAUzaVM0o6VTdSJHYt18fvUDWH3y6A
         aqMyDR9Q3bpFgLy+dcK/Bk0d/e+wCMwAnxxT8fyea267rGklw/mbdv2iiMQL5plTmdZn
         Xt7g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1709935389; x=1710540189;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=GG10uVfrxxhkT0zeNzC2jkcOo+aOgfVZquqGbOZ5l04=;
        b=cxzRYF9JEPgOyyXTl1tO2697tPU8T4zE6fZfZqHZ9oDKLcn3PB2BeT5+IAC5o5KibJ
         xbWiBdTklxYXO89iAnkdiVcRI/LxwtOel/znqnW29CCQi0KOIvQdp1Nd3pDD8KKrh/T2
         d8JoDySdI6uL7ByOGLYKD5G7SB4At0/3T75IpnH02F78KeaduyjVounebecqgw8y5utH
         ApL3XtkpsW/0nkuRPzYaUoFnoNgdeCZyy45QPuQrItX1ifewZwDlbTdCgU2UOYfBYO1u
         gVud4Z8w5o0nwU8prsbuQB3y1DQ8VNqNcgUGLcL7kq8Q8sGofCj2nLQC494a6FyhHdHt
         ns+g==
X-Forwarded-Encrypted: i=2; AJvYcCXMHHvuuaJEu2RJ4BfIjDpQHt/A5vwTwOnDOi+tTdDvdl/7demgBdKD9kp3bTQ2csMkZhHxiU4tl38+B4DQ5Js2NSR1IJ9Jdg==
X-Gm-Message-State: AOJu0Ywbm3GWHwrEY/zNF1OJTa/eKyKIQPu1A7WzaZLqsGnS5RwSuAy8
	YZr5RoZWfn8dEz5YreYJYS+3QvkfWzLm5iLdalHq8PgVKDxb0R+y
X-Google-Smtp-Source: AGHT+IElZ88Za9870FWJfYbcCRAEsqstFDAcOhW9IdGpq6PDh86hhze2Q8Ze0ptpVII48zikC1NB/Q==
X-Received: by 2002:a17:903:230a:b0:1dd:67c1:b4f0 with SMTP id d10-20020a170903230a00b001dd67c1b4f0mr288894plh.12.1709935389172;
        Fri, 08 Mar 2024 14:03:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:5514:0:b0:5a1:79e4:2080 with SMTP id e20-20020a4a5514000000b005a179e42080ls2131147oob.0.-pod-prod-09-us;
 Fri, 08 Mar 2024 14:03:07 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXdKVMPfeKjzR/mwUaVQahCCCQe8ZFLm9ry8a2Zu3r6LzEwAQlgWQneurZhIpMdEASi5eNfU/x1WI9uuXbfZ32NTzIsKbBY9CEFeQ==
X-Received: by 2002:a05:6808:3989:b0:3c2:3bba:c9ec with SMTP id gq9-20020a056808398900b003c23bbac9ecmr140844oib.59.1709935387682;
        Fri, 08 Mar 2024 14:03:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1709935387; cv=none;
        d=google.com; s=arc-20160816;
        b=eh4Bukm3qnUu+XGpzRS5w0Ot+y7zbGHZES7ZZ20cK/m0wJ3hU03K/FmYlo94v9iqPW
         y8qEr9cNUEIHzLwKX2L2Cp62uDgxraBjFnTTO271STTVbkZ6EVm/q2+dqPJqIsFYDnsn
         ZhiOmCjoum8nV1ilJVri+oiT8xg5M78itg37en0O0o0uMoJ2bYSHo3AH+ukZIfA7KFM/
         uzTdsWCztov9dhTu2suoMKYV6ueqFmZJIQKj3m1NGFRqwKHb3boh9Iwrsf3ySMQRtsfh
         7MvStcLIzKXl3YDJDZpkJ9lBzAZcEiz2VAWb/agQrlEiCF5FIBAkI+6E6MplM64ZVfUx
         bqrw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=aCHYD7g5w02qkYJ98Gf28OBGdeZeHkIZNRO5BYbEl3o=;
        fh=ntomV8iYpfAyXHtPw2HZna1E6drzRjxYRQ5MOzAVLzE=;
        b=rkD+B6w6t77ntnbbd3uTm8ommImTxBK5P3tE0ZjqUw0ABjaptZ+7WCC3EO4um96wIw
         YbAo2f8wNNAfMjRS8g58EMoBmb2M3DaY1dsSGqgvA3WsLUquRApWjvXnESO1obQwSQtD
         rEXICoHxdMcAjNPdulnr4xYaHOKT0o/E0vW7K8Qh/WPmZr1KB/Mu5ocd7/9IVS/J2vi3
         iI4N78sv8/xbgdUG1IuqUHcFynkiQdig7CXeLSZQLF5BPLRG3CnOMJ1o+9Vwlx5Dmlkc
         2+u1p/pw+UkIll+n3AFETf59Fu6ADmBkRNOhsMueT1Wl+R9cG08CMK3kYVfbc2vVL5i1
         nqyg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="Iu/zdOS+";
       spf=pass (google.com: domain of elver@google.com designates 2001:4860:4864:20::35 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oa1-x35.google.com (mail-oa1-x35.google.com. [2001:4860:4864:20::35])
        by gmr-mx.google.com with ESMTPS id bf1-20020a056808190100b003c1e7ccb8f2si57061oib.1.2024.03.08.14.03.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 08 Mar 2024 14:03:07 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2001:4860:4864:20::35 as permitted sender) client-ip=2001:4860:4864:20::35;
Received: by mail-oa1-x35.google.com with SMTP id 586e51a60fabf-221830f6643so1043409fac.2
        for <kasan-dev@googlegroups.com>; Fri, 08 Mar 2024 14:03:07 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWWpnEXFMPgjcgysL2AnJxdFZBygYda7ZQ+JHuvBG0I2uafPSbSsQm/hcm1a7gAE3ZAEc4qRpgGbkZZPZQRa7Rq2rNzKQi10xp5vg==
X-Received: by 2002:a05:6871:826:b0:221:864f:8c6b with SMTP id
 q38-20020a056871082600b00221864f8c6bmr414011oap.44.1709935387127; Fri, 08 Mar
 2024 14:03:07 -0800 (PST)
MIME-Version: 1.0
References: <0733eb10-5e7a-4450-9b8a-527b97c842ff@paulmck-laptop>
In-Reply-To: <0733eb10-5e7a-4450-9b8a-527b97c842ff@paulmck-laptop>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 8 Mar 2024 23:02:28 +0100
Message-ID: <CANpmjNO+0d82rPCQ22xrEEqW_3sk7T28Dv95k1jnB7YmG3amjA@mail.gmail.com>
Subject: Re: [PATCH RFC rcu] Inform KCSAN of one-byte cmpxchg() in rcu_trc_cmpxchg_need_qs()
To: paulmck@kernel.org
Cc: rcu@vger.kernel.org, kasan-dev@googlegroups.com, dvyukov@google.com, 
	glider@google.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="Iu/zdOS+";       spf=pass
 (google.com: domain of elver@google.com designates 2001:4860:4864:20::35 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Fri, 8 Mar 2024 at 22:41, Paul E. McKenney <paulmck@kernel.org> wrote:
>
> Tasks Trace RCU needs a single-byte cmpxchg(), but no such thing exists.

Because not all architectures support 1-byte cmpxchg?
What prevents us from implementing it?

> Therefore, rcu_trc_cmpxchg_need_qs() emulates one using field substitution
> and a four-byte cmpxchg(), such that the other three bytes are always
> atomically updated to their old values.  This works, but results in
> false-positive KCSAN failures because as far as KCSAN knows, this
> cmpxchg() operation is updating all four bytes.
>
> This commit therefore encloses the cmpxchg() in a data_race() and adds
> a single-byte instrument_atomic_read_write(), thus telling KCSAN exactly
> what is going on so as to avoid the false positives.
>
> Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
> Cc: Marco Elver <elver@google.com>
>
> ---
>
> Is this really the right way to do this?

This code has a real data race per definition of data race, right?
KCSAN instruments the primitive precisely per its real semantics, but
the desired semantics does not match the real semantics. As such, to
me the right way would be implementing cmpxchgb().

Otherwise, the workaround below is perfectly adequate.

> diff --git a/kernel/rcu/tasks.h b/kernel/rcu/tasks.h
> index d5319bbe8c982..e83adcdb49b5f 100644
> --- a/kernel/rcu/tasks.h
> +++ b/kernel/rcu/tasks.h
> @@ -1460,6 +1460,7 @@ static void rcu_st_need_qs(struct task_struct *t, u8 v)
>  /*
>   * Do a cmpxchg() on ->trc_reader_special.b.need_qs, allowing for
>   * the four-byte operand-size restriction of some platforms.
> + *
>   * Returns the old value, which is often ignored.
>   */
>  u8 rcu_trc_cmpxchg_need_qs(struct task_struct *t, u8 old, u8 new)
> @@ -1471,7 +1472,13 @@ u8 rcu_trc_cmpxchg_need_qs(struct task_struct *t, u8 old, u8 new)
>         if (trs_old.b.need_qs != old)
>                 return trs_old.b.need_qs;
>         trs_new.b.need_qs = new;
> -       ret.s = cmpxchg(&t->trc_reader_special.s, trs_old.s, trs_new.s);
> +
> +       // Although cmpxchg() appears to KCSAN to update all four bytes,
> +       // only the .b.need_qs byte actually changes.
> +       instrument_atomic_read_write(&t->trc_reader_special.b.need_qs,
> +                                    sizeof(t->trc_reader_special.b.need_qs));
> +       ret.s = data_race(cmpxchg(&t->trc_reader_special.s, trs_old.s, trs_new.s));
> +
>         return ret.b.need_qs;
>  }
>  EXPORT_SYMBOL_GPL(rcu_trc_cmpxchg_need_qs);
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNO%2B0d82rPCQ22xrEEqW_3sk7T28Dv95k1jnB7YmG3amjA%40mail.gmail.com.
