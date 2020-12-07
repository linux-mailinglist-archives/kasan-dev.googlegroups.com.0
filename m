Return-Path: <kasan-dev+bncBDAMN6NI5EERBQOFXL7AKGQE3TLFR2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 05EC52D1C46
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Dec 2020 22:46:42 +0100 (CET)
Received: by mail-lj1-x23a.google.com with SMTP id n10sf738377ljj.0
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Dec 2020 13:46:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607377601; cv=pass;
        d=google.com; s=arc-20160816;
        b=JWA8n5xKYRk7irOWugI6BNm3iJYAYUehSl9g58ImTl9PZdtQ+tPhU41uO4xQR9dbe2
         +VT5+KvI+s5UzVtHB/NpHIpTqMWuE59KaMwypMb3SK/kTXWI+zrJfYsdnA5vHyGs6D32
         VzYFHuQc+ZIn5IAWDkfvt3AXsYicBcsMs9DBuvbt013KeI1MufQIV9jRY9UxGZbFGOeg
         mUDDeGLoFyKZMv1wqUwTevCwRBQdYKFEx0eK0fbgLhzrfJO1TqQocyuiAgQRfZpUPO2v
         Nq169BLQhgiZqjUu+eYkYmaAR+XmtVmruT0uX4RgtO5K9OHX/Z/KoIYNwWE9vylpvO3w
         FTIA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=ETQBdLzEdrfl2XYhvJF3hCtTjHpNVlDUoh2V4Sm33Ic=;
        b=gDmDiWY9LxGlTLIm7DgEmpIW3ow5WBRqJJ0sRHWwPgS3CLQyUAWtmFQYQn7z5GCfr/
         khvL1BjscBhPZ5dmr5ogOg4dssBbXbzDeV1gCLRk1JG8vcWAs+ky4kQdX9CxAP+4DFLa
         8UpgUutkPziUMjSeEMmMk9sKs4WY9CvxyvYL6J7CwUMuweQKwD+bO6VfrW1CyUrUNzs2
         Hcv3GH5kXtEPWvQ4AS/sxz9M8YTpXLD2beFCdUrmamtK+uBPAqBIMbBziyUTnhFLPCT8
         vUUlxNsNWh5e8HWLTn9Q0cp2kKYattnS6EqxoomJWOiCqkVAGnyBzlK0ot9gizElLw19
         2img==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b="ou/lhMrI";
       dkim=neutral (no key) header.i=@linutronix.de header.b=GWn3H1bK;
       spf=pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ETQBdLzEdrfl2XYhvJF3hCtTjHpNVlDUoh2V4Sm33Ic=;
        b=c3+QP/7r1DeSLvczj6/rbYQwXn8FmOPB4BnkjJbnqFOYE+s+toLiAcXhVxWPtedfB4
         hUG5bFhq207llSgTA+7NAZS++aeoqz/sIJ3SKr0deRZcce/gQc0XRkXV9QYbi+NM7lN0
         PayOjQyx3BIdZqlPesHSHEaP746KChHu7FUXPAueHmy2KOycHV66me53vI5Ei6XNlTYJ
         bFDMJTKLCVliCZwNSWCiaD7aCWaErD1+mWJG3A2d4J69h2qMGXSD34WuBlvBTf2dBMwk
         v1bx8yXpr7E8G1lEp4FhL5j93NXoGMUyEX6x+Tkgl6L0rudljFrRi9UYoOIHgHkE1PYY
         iWhg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ETQBdLzEdrfl2XYhvJF3hCtTjHpNVlDUoh2V4Sm33Ic=;
        b=G9UIVyQQI1Q8E2WhkH4IyO7ZZy1UrU+bjwm6JlItHuDMhaRBaJ9DtAtNbM/nAYUDYL
         BzON/82ovKOfhtsVp+yM4jirxqCEQk+Ezwsdc82DgnTe0lwnO0CjwPw0Vae05JuqV0Hp
         RWJIhBXZNdTYq3Z3rsR+YWAj5jNpRR8+f/GPrmqtPhm8oKxPwJKH9Wf0Zuj+0qAM4uq8
         RwTtfRzXXbnLnpwMa3uNf/QXeVnI8l4izvCh+hp20mjk4psn98oN6tXB15JXGpVHD+zB
         5B60U8YHKZeXTjnoXUvrcPhNe/WrKvOu1piSIQitqESzO5O4AhjvHO3OoX2NrUwF9i0h
         bDjw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530XhNC0yyEhtFx06y5WALZcAGW+QXP2H1+uVBMbmyQqDPmW27cX
	hKRD53fpcxPinnfcRZUleUU=
X-Google-Smtp-Source: ABdhPJxhL3xShNJ+G9xdsk3iL1KQ91PCVCtqQoY+ewNlIw1/TK5naDJj3xPAoG9GWmMghVmW7ZEh9Q==
X-Received: by 2002:ac2:4465:: with SMTP id y5mr9376102lfl.172.1607377601546;
        Mon, 07 Dec 2020 13:46:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4942:: with SMTP id o2ls2097273lfi.1.gmail; Mon, 07 Dec
 2020 13:46:40 -0800 (PST)
X-Received: by 2002:a19:cc4:: with SMTP id 187mr228835lfm.120.1607377600514;
        Mon, 07 Dec 2020 13:46:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607377600; cv=none;
        d=google.com; s=arc-20160816;
        b=sBIpZlg50vrkIEnFsLonhzxfHUoPkmDwWa72qLhqbQ560S41a20aa3eDnqpyQHdSRd
         e+qomdLW8PQcEJwdsFzppYsOzn23sp+JXGXpnEUnizPIfhc8rS+OJMRbIZWTyljpzUNz
         huMLeFJZ6iJlCTl06ilb+G3SSHCI3ePSfnl3a4cIb5ByGGPQ3ong0J3Qj7kNrP4JUADz
         b++71PVsh59m3dNfH99ZH8SQWNyEIHpqiRtmhWEoNMvTNRII/g4XiBqc7DzUyMD7gmLe
         jpaDy5XlA7PODgk+HZ/WjcKmdMET/nmnLO0Va7GSOPP5Xn7UD73lT2VfS5E98w73cmTd
         +/cA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :dkim-signature:dkim-signature:from;
        bh=XezsoOvo1QH3xJ+aBZ86D9VZCPnhkhJ5Z+Xl0ZlweKY=;
        b=P/V81FOQ+mN7SnE+BPQuGyq9RZlood3AkL9+kzCk1bsF787L2Bs08jYAfjDeTkfvya
         vt+NkC44xnriNIDMP/IWNAL/8tQg52tzhT5faJKINNv5O8htSPXaWGb9PewhNxPRTe6R
         VAlj0gf/gcCbUh4G3GjWbemqfYPRrbluIKq/zYrwGb/BTSTHxL3uDz20aKouo9AzoW4W
         KVdkTgDvu50ArQxD/VFcHcazRaPMWYn5h0KQjnhu7uPUHqB+YuRRXswgdCe2QzHtUjP2
         fT4iCvW5lewO2TMSj6M8X0H1qNLtmJ382GWbqAXUDptWQrVkZ5frFb3S1LrkA+6XMj+0
         XKlw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b="ou/lhMrI";
       dkim=neutral (no key) header.i=@linutronix.de header.b=GWn3H1bK;
       spf=pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [2a0a:51c0:0:12e:550::1])
        by gmr-mx.google.com with ESMTPS id y21si591917lfl.7.2020.12.07.13.46.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 07 Dec 2020 13:46:40 -0800 (PST)
Received-SPF: pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) client-ip=2a0a:51c0:0:12e:550::1;
From: Thomas Gleixner <tglx@linutronix.de>
To: paulmck@kernel.org, Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, Ingo Molnar <mingo@kernel.org>, Frederic Weisbecker <frederic@kernel.org>, Will Deacon <will@kernel.org>, Naresh Kamboju <naresh.kamboju@linaro.org>, syzbot+23a256029191772c2f02@syzkaller.appspotmail.com, syzbot+56078ac0b9071335a745@syzkaller.appspotmail.com, syzbot+867130cb240c41f15164@syzkaller.appspotmail.com
Subject: Re: [patch 3/3] tick: Annotate tick_do_timer_cpu data races
In-Reply-To: <20201207194406.GK2657@paulmck-ThinkPad-P72>
References: <20201206211253.919834182@linutronix.de> <20201206212002.876987748@linutronix.de> <20201207120943.GS3021@hirez.programming.kicks-ass.net> <87y2i94igo.fsf@nanos.tec.linutronix.de> <CANpmjNNQiTbnkkj+ZHS5xxQuQfnWN_JGwSnN-_xqfa=raVrXHQ@mail.gmail.com> <20201207194406.GK2657@paulmck-ThinkPad-P72>
Date: Mon, 07 Dec 2020 22:46:33 +0100
Message-ID: <87blf547d2.fsf@nanos.tec.linutronix.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: tglx@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b="ou/lhMrI";       dkim=neutral
 (no key) header.i=@linutronix.de header.b=GWn3H1bK;       spf=pass
 (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1
 as permitted sender) smtp.mailfrom=tglx@linutronix.de;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
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

On Mon, Dec 07 2020 at 11:44, Paul E. McKenney wrote:
> On Mon, Dec 07, 2020 at 07:19:51PM +0100, Marco Elver wrote:
>> On Mon, 7 Dec 2020 at 18:46, Thomas Gleixner <tglx@linutronix.de> wrote:
>> I currently don't know what the rule for Peter's preferred variant
>> would be, without running the risk of some accidentally data_race()'d
>> accesses.
>> 
>> Thoughts?
>
> I am also concerned about inadvertently covering code with data_race().
>
> Also, in this particular case, why data_race() rather than READ_ONCE()?
> Do we really expect the compiler to be able to optimize this case
> significantly without READ_ONCE()?

That was your suggestion a week or so ago :)

Thanks,

        tglx

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87blf547d2.fsf%40nanos.tec.linutronix.de.
