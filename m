Return-Path: <kasan-dev+bncBDGIV3UHVAGBBLGSXD7AKGQEBDQFN6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id DCECC2D115F
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Dec 2020 14:07:56 +0100 (CET)
Received: by mail-wm1-x33c.google.com with SMTP id u123sf4112219wmu.5
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Dec 2020 05:07:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607346476; cv=pass;
        d=google.com; s=arc-20160816;
        b=BILP44bj4eIjbKgbuY3V0tbGVDBLVYdZO4S1udG6mpQ4vCilUe8LZKrYD+zp+dfsCx
         9BnWl67QnpyRNibSKAvwjImUnk0yMs99foSDQ7CcOS5bYMCObcjt+nkTLHWnKW/vm4eu
         c+Az727RgyFjiDXFv0wm8p0FA8jJetfvpbtUtuaYFwcQKNvo3TUMOwZYFtkZDITz/rLA
         cewixnb6f1jv0z329NToUy+fUgYFJsYgw3u55Sio4sBV0BYTpbKI9GNdqvvchB3YinGS
         8euOcny44DipmP3/KstUEnkXbZqzVehwWV5DEInC1Y6RmdjneoEXtB6VmmHUb8qd1eVX
         nRsA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=Vj5K9FtpK+QxlJ0LZCENwid5zj11ULQAsCbfEucXPsM=;
        b=dxjl7pmI50bcw1WBNfgtgff931R9yPJka7wVML1ZSkcjuwux4PnAiZKeqYJgfEricU
         EgxGEctKSc86UkXUSdYSidBNT/iag6VYSEey0OYndY4IVT3I1iH3t6yk/+4DgA5QfF5/
         zMbnBTlzb93OSP5VRqV9B21QlnJYop7bP5UBeF1CKKyFTa3HAClC+9a/HuW83ZXhn6KE
         ubuv4pLg6LEheXSYFF7NNjai3R7FLm+SYujQAZjEBBZ3LdL1GyzJm3Wh+L1nRu7qRv6/
         fPB5R3rqLqJU/UDW94W3AbwJFHJvBzI1a2HpMA3WSoFs6VlAzYbRW2ytyiIkT4oCcBJX
         cH3A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b="nxkMd/2j";
       dkim=neutral (no key) header.i=@linutronix.de header.b=D4cM2G2T;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Vj5K9FtpK+QxlJ0LZCENwid5zj11ULQAsCbfEucXPsM=;
        b=rY7RsJvRdVfs+5QPo4NIFk0Vsm7HtcU6XEeVnqAohxcZ71vgvh+qgudc0wbhaESStR
         8J/KIYioDuZHRwoon7xEC3m2s+iwMiR0nddhmfzCU507xfaqD5F4rpiSGX0j1DVPaviL
         aZnZdfDaR3E20HQsJA7c5CDbQsUEXwjScfcNUQ3JdeqkCdBfIy2+l1412Nb4Lw8sWxqz
         YggvdstbstqvYM3x3P46Hr2gHfZXNnOaZKyU9vaBomWDOV6p42qn1y7o5izNl9cQ78bn
         QWz8YtGZLQfac6SAJW4KMtsGGKbrR0LAk7skFLj1Dp4Hy2Z5DFFQUJP/A4QrpsNbA53R
         cjxQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Vj5K9FtpK+QxlJ0LZCENwid5zj11ULQAsCbfEucXPsM=;
        b=iHjY4Rq0JemFf19mJYECwZx20P5Ght/YW0oODqHxmlO0YbH9G4Q08SQB9Y20TVAroI
         C1A5DKExXoOdpLGecuCq5ZazKD1QZOmiNjx4qC6eZok9iT756rS2/fa1rC4hqDv+Gytj
         b33anE4pQ8GxkKqKbPWD6Mfh0QlfJrI6qdJWJC7WxnluXPqPaKb16XUPdvHSuBEsFV2a
         GTsqPc6DqcVzupMdHVb+CnUMzrqj3T+XG2mnWFQxYgD3XEmCOgDDdLK18/7d7hzuFWBs
         lI9CEmBOUsnQODqZc9PxCEAZKdpHVzxkrhm7lT+tYaK2HZvS6AG86g9RTm/oUBj4ADCZ
         NJKg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533MZnPMRw4ASOyhEcEv4mKXQabDLQhVjh9DjBvbkPWWiun4NEv+
	1lc3Fuirwv4IfkXS5HP0qJU=
X-Google-Smtp-Source: ABdhPJxjm3xSCuKoTiYbVTio/ezGh6O3jn5XpF1YE+m/x0Q2Y+L1VIhq6qT2fv8zuiM7Qafjiu5elQ==
X-Received: by 2002:a1c:2182:: with SMTP id h124mr18258351wmh.25.1607346476622;
        Mon, 07 Dec 2020 05:07:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:2094:: with SMTP id g142ls4840616wmg.2.gmail; Mon, 07
 Dec 2020 05:07:55 -0800 (PST)
X-Received: by 2002:a05:600c:2:: with SMTP id g2mr18042322wmc.156.1607346475745;
        Mon, 07 Dec 2020 05:07:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607346475; cv=none;
        d=google.com; s=arc-20160816;
        b=N626yJE66mCv9W5pU5pj+W9LuURvMy9s1ftxOlDuqsP19BEdqGe2K2DuLdxZQYsw/m
         2PkOUIpiy77E+EHjvSl37T/N3InIilsFVlYZoyRvzFlvw8neGUgVhAL/PMcxPSHINftR
         cimHSeWq8hIs6va82ChktTGcAZAe3ZZnwvkwWNToTYeu3A51QPJ7OzocknlGsJwLjgAL
         JbnKC48mMo405Iw3DdP8RHL9dP8gCwEt5xPIHMv05URFR5S4kwIAEajlkQy2vL/0I40e
         LF/R3usbG3dn4e7GDD99zMJACEDw4NBTpNoEZ8Xq4HygSY3rpTlWJ8W6o/vquAj0FySL
         vviA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:dkim-signature:date;
        bh=AEcL9OhL6kwohTTMJroOIYcIaDEJ3dPqe8/HW1T46I0=;
        b=YicFNM9TGcUwSJwT9cc8rznYYWLyytI40iTrkCRPeyHfX5hijzibrYCZCv6xcK1WVZ
         BasLesPPV+boo0sB20TjTfGdU+uFJNde2jMW/6tfu4B7IenJyyUX8li0Jf6HF6yEPU5+
         SSKcLgckN2W6cNe7cf02JoUQpFwsIkU4ySxoAglwuqUT0w/Wdmz+lAdkhM7YJkNkYaWF
         Qt51Ll/bd9432zzEV6ddLxaNLpN3gTPqjxy9MvgKfjC7OoUk6odn99e59TG7TNoDOMDW
         BjiB7R6XFJGIv1kx+CzdgWE1GRmVDAPTVZF6B5QvyD2D/WbjshA4ZwDbWoE6y4AO7wXS
         6pDw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b="nxkMd/2j";
       dkim=neutral (no key) header.i=@linutronix.de header.b=D4cM2G2T;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [2a0a:51c0:0:12e:550::1])
        by gmr-mx.google.com with ESMTPS id x130si256472wmg.2.2020.12.07.05.07.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 07 Dec 2020 05:07:55 -0800 (PST)
Received-SPF: pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) client-ip=2a0a:51c0:0:12e:550::1;
Date: Mon, 7 Dec 2020 14:07:53 +0100
From: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
To: Thomas Gleixner <tglx@linutronix.de>
Cc: LKML <linux-kernel@vger.kernel.org>, Marco Elver <elver@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Peter Zijlstra <peterz@infradead.org>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Anna-Maria Behnsen <anna-maria@linutronix.de>
Subject: Re: timers: Move clearing of base::timer_running under base::lock
Message-ID: <20201207130753.kpxf2ydroccjzrge@linutronix.de>
References: <87lfea7gw8.fsf@nanos.tec.linutronix.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <87lfea7gw8.fsf@nanos.tec.linutronix.de>
X-Original-Sender: bigeasy@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b="nxkMd/2j";       dkim=neutral
 (no key) header.i=@linutronix.de header.b=D4cM2G2T;       spf=pass
 (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1
 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;       dmarc=pass
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

On 2020-12-06 22:40:07 [+0100], Thomas Gleixner wrote:
> syzbot reported KCSAN data races vs. timer_base::timer_running being set to
> NULL without holding base::lock in expire_timers().
> 
> This looks innocent and most reads are clearly not problematic but for a
> non-RT kernel it's completely irrelevant whether the store happens before
> or after taking the lock. For an RT kernel moving the store under the lock
> requires an extra unlock/lock pair in the case that there is a waiter for
> the timer. But that's not the end of the world and definitely not worth the
> trouble of adding boatloads of comments and annotations to the code. Famous
> last words...
> 
> Reported-by: syzbot+aa7c2385d46c5eba0b89@syzkaller.appspotmail.com
> Reported-by: syzbot+abea4558531bae1ba9fe@syzkaller.appspotmail.com
> Signed-off-by: Thomas Gleixner <tglx@linutronix.de>

One thing I noticed while testing it is that the "corner" case in
timer_sync_wait_running() is quite reliably hit by rcu_preempt
rcu_gp_fqs_loop() -> swait_event_idle_timeout_exclusive() invocation.

Sebastian

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201207130753.kpxf2ydroccjzrge%40linutronix.de.
