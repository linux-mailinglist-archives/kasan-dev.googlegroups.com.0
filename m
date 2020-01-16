Return-Path: <kasan-dev+bncBCF5XGNWYQBRBFXNQPYQKGQETNQIW4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc39.google.com (mail-yw1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id 029DC140032
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Jan 2020 00:49:44 +0100 (CET)
Received: by mail-yw1-xc39.google.com with SMTP id y188sf23908742ywa.4
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Jan 2020 15:49:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579218583; cv=pass;
        d=google.com; s=arc-20160816;
        b=gF2a3Z/mkKbO4uHcqu/PJEsezKVlyn6gjRLOiqcpXtfEtfKNmEwWx6vWtyGFmA4syT
         vWx0TSCyLbsn8gRcVRsCOp8VdClt6VX3CF41EEdM23N8VnO4kCd9DBj85Mwv+gSdULVo
         0aYQYs/CvLvzGGp0+vRfFSBylHTXhI4vBBitRyVROhPSegsjJHg7qXz8xi1wfrYtK2Au
         hFmSK13cCzGG6s7Khzezu9S6Pc/xYdb0b5UXixLWSQAB6IAj+uQ2sXhCSSVdQ9Q6qjp2
         qinpOxyxHkA1t3Te6fsGcoHqcUlORMdPCLGwfRmWTjHo6PWu+gkNx7ybGsMdebLHpkCZ
         kGfg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=0xSAT5N6JGt1wbDzW9ZJao2ikaAr0+7OEv04c8MGKwM=;
        b=Do3ISvip4scNlr6YffRHmJ/HY01+74tSdNFif3gk9+KNw9RrkBPl1WKo3ZZ87sGo68
         yvVt+OgJzX2IzRZHSkpw6Vc9tRL4J3KsyCeqB5VUaUHlAM7JTbvv7b/fEGsHkHUe/GmE
         en0rnjflMKmZX0VWVev9c1XmQjLgF0mkueRa0sDDvbp19XpGI6KpUsSUPX69ig/XAtm7
         iVEWL+/CW9DAxOWN42GEOMSKhtnq92HlFlltEu3xjomFcLbMeufJj5116ykkBKUV2RSH
         0elt2vYkS7RR79bFHYked35dbAY3QkSpuM8Cz5UzPQRtbPc6Gy+CCryCMakOCdoFBGiX
         p+rg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=KwvjQE6K;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=0xSAT5N6JGt1wbDzW9ZJao2ikaAr0+7OEv04c8MGKwM=;
        b=rVb/287lkRaNcc7n4wshnSxs3zDh5ShmQt2ueUEc8XIvEjF3nVETG5ITabohFEWJFY
         K9PzOVveKYL2Zuhq5NmyeLVYiFq6hFEa0QV5MmKcIxlIfxmS7DLZHlquNc4iFiLQDPMl
         guIkSpdYNRa7736f1q80FhIre1WH/kZlaPkG8tlBg31rTBfAOxbZ6wtzx7ZZPBL5kSVP
         sVhzDccNwpVpHiWNQqSkpBAuEBUmUDGb9op0oHkXnTzs8h9isviTc2EnlAZ4E4RQPqMY
         1nyj4Vuf6AetQ30PFtdBqyRtPTZNG9/SpqTOpssmu9F+5xpe+Mj3aI6Sz77LHcRokBy0
         dcbw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=0xSAT5N6JGt1wbDzW9ZJao2ikaAr0+7OEv04c8MGKwM=;
        b=Yh6bdSwcBMAbwjUHyL+b4ag/Mbe9OSXHmCAc9ojdxYBI/V6M8TWkHRbTj9tgVHZz4/
         T+FMmL+5mfyxE8afCIP3804nF6iQkFeejWbN9aXZ6QWps3uw/oXPJudqj1j2Tb2uCHSv
         qfJpohQYTlvQ3XzN3qPFfEAFezdWPVqBvAGE9iuYPDbmWIKhYe0Stx7PQFF2xkxdZMd5
         jYB9zby5spz8x31LCRicIqYJZ8KZapDDwTCer1t0tIEOd2YlOsuig8QrCKgLRXP2NNrO
         WslDfwjg6+Ox+ro+3Hirk26hVdP8uIOnrCKJidWpVlAWRIA8Nf5GjetSu3ufZlx0wb9x
         UClQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWX/tnEAuRz3DDBE5rwDUkLJp8SKfAhq5NIMvmDxmDwxTLR9X7z
	LwcU7zvh+R43nlWTpap2zis=
X-Google-Smtp-Source: APXvYqzT/o98WXoiwTSQDtOWyr4517GK48+G+JKaJJ54eCd3H36839MWrxAQADVyly3GcXlkXdoM+Q==
X-Received: by 2002:a81:a1d3:: with SMTP id y202mr27370589ywg.300.1579218582960;
        Thu, 16 Jan 2020 15:49:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:5f04:: with SMTP id t4ls3837129ywb.12.gmail; Thu, 16 Jan
 2020 15:49:42 -0800 (PST)
X-Received: by 2002:a81:a503:: with SMTP id u3mr29072783ywg.118.1579218582559;
        Thu, 16 Jan 2020 15:49:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579218582; cv=none;
        d=google.com; s=arc-20160816;
        b=M8OK497d7Xl9GyekLW5OX2C3N86w+lJDrbi9MaqdRmJPSrnFwLo63AuUl0SJg3X+tu
         MrFccVM7Ec2feBlM5iegoIBxiYDyPNCQYuHEK+7ebtF0WiHsB45RjSKUKGJRZhvrtZUX
         ulBCSbAld3NQkQDsvzaqbCiocIq0RsTA8KOuqKJqBJa/+edEKT53EyhPWVkBRekkTQ5H
         0kKdn9lEZKgpQgvBCMehf4AC/q8L0U2vM2yLH7FBw9fAumBv9VGlYwazLVfqivd7n5wV
         ArAjVo5qWsY5DBTxz+UaTDDOzz2N92T1LuxJVBS9xVMrGpphCK6ljBf2OunZsTvWAN8Y
         2hIg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=OBxWYYcj5NPKpHkfAvk0D+yaQt02q3V7O1jMrLi++8s=;
        b=E1ZWWe36OkAcOrrY/Gah3Q1pX0bzBoKLV0CYEnqsoyI6UOyMtkOXdjClOyzksTBD9V
         3dCrIXjhyCbTbBqnYvWBdyjCD784/6+SgPRj46LoDMqUWbtv2UY4qe5ZdizGlA2OlAQB
         2wZuLZbIF0dTvF16GMPtJWZxZ9ir1JrAZPmugKhqLH0Bhk20PY95wf2AJ+Ez/viaz1Y+
         KeY/RtgfFon4TgaSKBDtufPCTf3LVivJlDV+0DAgRNyK71CBEt+Dm5LUr0EqqqjK7ljV
         roFFQr8loj/Ssu0OvNr2PC8kimQhV8XQLlhzOvv1D8na7R7fub5xKMOPW1HCJ1n2lR09
         efyg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=KwvjQE6K;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pf1-x441.google.com (mail-pf1-x441.google.com. [2607:f8b0:4864:20::441])
        by gmr-mx.google.com with ESMTPS id p15si1040417ybl.5.2020.01.16.15.49.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 16 Jan 2020 15:49:42 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::441 as permitted sender) client-ip=2607:f8b0:4864:20::441;
Received: by mail-pf1-x441.google.com with SMTP id x184so11036187pfb.3
        for <kasan-dev@googlegroups.com>; Thu, 16 Jan 2020 15:49:42 -0800 (PST)
X-Received: by 2002:a62:158c:: with SMTP id 134mr44301pfv.81.1579218581788;
        Thu, 16 Jan 2020 15:49:41 -0800 (PST)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id p5sm25618874pgs.28.2020.01.16.15.49.40
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 16 Jan 2020 15:49:40 -0800 (PST)
Date: Thu, 16 Jan 2020 15:49:39 -0800
From: Kees Cook <keescook@chromium.org>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Elena Petrova <lenaptr@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dan Carpenter <dan.carpenter@oracle.com>,
	"Gustavo A. R. Silva" <gustavo@embeddedor.com>,
	Arnd Bergmann <arnd@arndb.de>,
	Ard Biesheuvel <ard.biesheuvel@linaro.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Linux-MM <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>,
	kernel-hardening@lists.openwall.com,
	syzkaller <syzkaller@googlegroups.com>
Subject: Re: [PATCH v3 5/6] kasan: Unset panic_on_warn before calling panic()
Message-ID: <202001161548.9E126B774F@keescook>
References: <20200116012321.26254-1-keescook@chromium.org>
 <20200116012321.26254-6-keescook@chromium.org>
 <CACT4Y+batRaj_PaDnfzLjpLDOCChhpiayKeab-rNLx5LAj1sSQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACT4Y+batRaj_PaDnfzLjpLDOCChhpiayKeab-rNLx5LAj1sSQ@mail.gmail.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=KwvjQE6K;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::441
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Thu, Jan 16, 2020 at 06:23:01AM +0100, Dmitry Vyukov wrote:
> On Thu, Jan 16, 2020 at 2:24 AM Kees Cook <keescook@chromium.org> wrote:
> >
> > As done in the full WARN() handler, panic_on_warn needs to be cleared
> > before calling panic() to avoid recursive panics.
> >
> > Signed-off-by: Kees Cook <keescook@chromium.org>
> > ---
> >  mm/kasan/report.c | 10 +++++++++-
> >  1 file changed, 9 insertions(+), 1 deletion(-)
> >
> > diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> > index 621782100eaa..844554e78893 100644
> > --- a/mm/kasan/report.c
> > +++ b/mm/kasan/report.c
> > @@ -92,8 +92,16 @@ static void end_report(unsigned long *flags)
> >         pr_err("==================================================================\n");
> >         add_taint(TAINT_BAD_PAGE, LOCKDEP_NOW_UNRELIABLE);
> >         spin_unlock_irqrestore(&report_lock, *flags);
> > -       if (panic_on_warn)
> > +       if (panic_on_warn) {
> > +               /*
> > +                * This thread may hit another WARN() in the panic path.
> > +                * Resetting this prevents additional WARN() from panicking the
> > +                * system on this thread.  Other threads are blocked by the
> > +                * panic_mutex in panic().
> 
> I don't understand part about other threads.
> Other threads are not necessary inside of panic(). And in fact since
> we reset panic_on_warn, they will not get there even if they should.
> If I am reading this correctly, once one thread prints a warning and
> is going to panic, other threads may now print infinite amounts of
> warning and proceed past them freely. Why is this the behavior we
> want?

AIUI, the issue is the current thread hitting another WARN and blocking
on trying to call panic again. WARNs encountered during the execution of
panic() need to not attempt to call panic() again.

-Kees

> 
> > +                */
> > +               panic_on_warn = 0;
> >                 panic("panic_on_warn set ...\n");
> > +       }
> >         kasan_enable_current();
> >  }

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202001161548.9E126B774F%40keescook.
