Return-Path: <kasan-dev+bncBC7OBJGL2MHBB26FTTZAKGQEODZLVQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd37.google.com (mail-io1-xd37.google.com [IPv6:2607:f8b0:4864:20::d37])
	by mail.lfdr.de (Postfix) with ESMTPS id 0FB0815F9EC
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Feb 2020 23:45:01 +0100 (CET)
Received: by mail-io1-xd37.google.com with SMTP id t12sf7727519iog.12
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Feb 2020 14:45:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581720299; cv=pass;
        d=google.com; s=arc-20160816;
        b=j5kflj5Pv13CP/X4T8RnQx5Z+Dr0AKvaXkhHAM1A/oLBSMDno6v/9DTA0SRbgTYHM8
         R+hAm5DOnpN3hxU9oaGrOMyzLCMtFQSOoc5JleAnguKlX84hGuDV1KSptQAMTlaf9vUl
         W0vAxTwdEoDB/Ygn9G6Q9/Kex1Tw8huAvWXXL2YnuEOP1IBeTdOCSJRpvtKMLVHifylE
         xoEte9QmpF1Ao9GOw47FcuRv3nF2+vD3q4ckOvvMeliJXqDU5NlzkMIkwNwDcuy8+HM6
         YL5dqQuA6JcZxeWcsVSMBB+ikVTzWpd+08iwCrzFsEZr5C3gofzwUE3+nui77kEAsRHn
         LXOQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=3bH5Q7EsOJ7znrJHfkB+3h4pxeHmJNRYVuxKJTeQJQo=;
        b=H3y7MXALIDcIK0FnqJ7B39akNp1is4dFqSPJd6dBwvKpPs5QGGbFJ9+uN23bXh2TVK
         bdYUtOvldzErbAKNcrcTAh69ODdc0sMnFWDeCqRKIFDNFy3VrGs442F2DolSkbmE8Z2t
         t2tr+nzvbEPNVmwlSQ/o2jaNycCEaH8AcWxI7zI69/OVTCSziUS8om2SPLBHVb7ghnYL
         0nKcJ1uNc7MdlVpr5fNOBScGf5Dsgu7DtLk9Y44P76o9+9ulmnDIEaGBIFu6idc8XDOc
         RUIjJmbSx7wjeGgmBfMeiOog97WQcaeGQyp/rd5QSKCJxtfZw23sm/t8nTxXlvKuOm9M
         pd0A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XC3OnI6J;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3bH5Q7EsOJ7znrJHfkB+3h4pxeHmJNRYVuxKJTeQJQo=;
        b=hn78Tz4rwNiQtxI0j4e18tDvcZAMsYnG9hQlBr/y+BMrkzMNnPn14oolVTNzE9iKj2
         jyPX3BxC0GecvtY0OGp+W6rWqIEDezAiBVOk50EM3uUzEgJB/aylmyDw+eHTcbxALJ6d
         aPvseoBw28PWwzzLtfg/JBJnEPO1r4eiQmRYEPsY/RL8ZOdSzHfl8ZhsXpFOiCKxw0K7
         eVgidCB6mYarPJQZNHwkWhNVzrYudKZC/C5OzE4xZat1trr0BOi6iYiVlXLmCtf+KIEC
         pgukzOOjCDAuOzCRNQIL1yJryW4AMompgJow3wVMF7OdlV/NblsqR7e6rVlMFcTbFnSg
         tdyQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3bH5Q7EsOJ7znrJHfkB+3h4pxeHmJNRYVuxKJTeQJQo=;
        b=MHjOVybWd4zJVKI/DXrcc6y0C808VwDBPI3VhXO9axGPZY6wR5UxmoDWoKdwA5kaZX
         mZnSGKuCQaAGAZoevIL1eJroa0e19SoT63aKrp584Pq++bsoA4Z3nH+5nb7sXr/Jlhc/
         GGHOx49YiKyRdUqFsv1SFf/3tk1RQIANiGkg8k1URpD1CWjMpKlJ27F4WNkC8x/3Oqiq
         7qN8EH5TtZBfw1cQrk2EA8fBsjHzAdA9YvKaN+3mej4KoyOGLhRLjSYJHUXvFurLbRuy
         4GIbTlceuyB06S53WrlmIpyIzBOxldnTT3sJyXXkzYlB508SHyNWKBd5RMlgcI4S2m2i
         PV8Q==
X-Gm-Message-State: APjAAAUjXae7lncEURF2jHCnSxMVQr+eRt67Ml2bL9Z75u2ukbYzfgjp
	hMcloSOTitXlRF0qPmf4CCU=
X-Google-Smtp-Source: APXvYqzt0HTLo5hTtFTaB2ggxR0C00TZnNgjruL4lQovx/AoxtcoOZRG6nXX6Cf4W1qxj8du4A150A==
X-Received: by 2002:a92:d451:: with SMTP id r17mr5063864ilm.201.1581720299678;
        Fri, 14 Feb 2020 14:44:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:794f:: with SMTP id u76ls849878ilc.9.gmail; Fri, 14 Feb
 2020 14:44:59 -0800 (PST)
X-Received: by 2002:a92:af8e:: with SMTP id v14mr4943532ill.150.1581720299340;
        Fri, 14 Feb 2020 14:44:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581720299; cv=none;
        d=google.com; s=arc-20160816;
        b=LDvfVX2wRUeYid6eOKj+kZBASH3dhYFjJUgh2kuygEE2GeWAHhZzGdDunrHNsjV78v
         E/bI0h6fnPLjuR9h5/0LL+wUaI2lO/EFV4UXo9z42tJrmfvovJmZwRmQootwn2EB4Z8D
         7PxiTnOMh6pcZtTn/6TA0vh2RjDqKXMqYPn9PHnlm0OGswTNQBtotkEjmPqmsYahx7WB
         N2IFoY4LuXteUjxlFaIPxzBlV6CfL9N3wFFo35/XDPtG2uWRpvhNc3LO+M2yXUThHXCf
         zxqyZIycP6X8CxRQfoq1MRULGrjQ9AFTffMtNtthSQ6G5Fbw70sUbNgUzqounaPVt53D
         L3Dg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=CpknVRHVvDf57dIIYiC8+zmpghtvoMSMWts+h9lgmTc=;
        b=d4LZWJ3VffNPH2RYv+UYIIK3ARbElBlYlzJavIgRUpI+ZFFZ6AOZG7sg0l0sTbVYwO
         6AnhhJr5aBlT5hC7e6m7A7HIUiSNrs44qyqlpmxxG8NT842joX7oca09CQ0kWFj6Clqs
         X81ZQOUO/p2lITPDRXmAmxXP0Ghn9wDVF+7sCE9uzOeZU21X/7QzgvJesfkM8N6L9AgZ
         1tqzqlukYZmX8h+Cl1PDajQWmvFSD51MvVzGMSJEamJWij9MqwGw7jZKu0YyzDVmHeA1
         z6Xu5l9m4AH/A1sml8yRgN9pFP7ocNZvHJpFJpYhEcfBT+NlI3/twghrdUf+3MX3nBYY
         jyUQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XC3OnI6J;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x341.google.com (mail-ot1-x341.google.com. [2607:f8b0:4864:20::341])
        by gmr-mx.google.com with ESMTPS id k18si373452ilg.0.2020.02.14.14.44.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 Feb 2020 14:44:59 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) client-ip=2607:f8b0:4864:20::341;
Received: by mail-ot1-x341.google.com with SMTP id g64so10659630otb.13
        for <kasan-dev@googlegroups.com>; Fri, 14 Feb 2020 14:44:59 -0800 (PST)
X-Received: by 2002:a9d:7410:: with SMTP id n16mr4158456otk.23.1581720298719;
 Fri, 14 Feb 2020 14:44:58 -0800 (PST)
MIME-Version: 1.0
References: <20200207120859.GA22345@paulmck-ThinkPad-P72> <1581088731.7365.16.camel@lca.pw>
 <CANpmjNPbT+2s+V+Ra3C-4ahtCxyHZzOLzCDp9u7c339vN6u7Fg@mail.gmail.com>
 <CANpmjNOXma=Px-EMMp-F5dij2BaF8iZFj-3WGCXf+bXrdtdU5Q@mail.gmail.com>
 <CANpmjNOdUZJz9N1ydecFrOgpqOMgwOT576dxo97XooPwwED3Hg@mail.gmail.com>
 <2C38E1DE-647E-4B90-98B8-D7F3C0512ADA@lca.pw> <20200214094423.GP2935@paulmck-ThinkPad-P72>
 <CANpmjNN17WCK=4=ZUfcKEARarYEheZ+L88JAKm-qG_zXM9DauQ@mail.gmail.com>
 <1581709863.7365.77.camel@lca.pw> <CANpmjNOqwS0OWduzsYRRygxpbtVR_x7vmWGAip73qj+caK+KXg@mail.gmail.com>
 <1581718076.7365.81.camel@lca.pw> <CANpmjNMi3jQaqEB54ypWh2xEKCVRzBesMMfV0zZBcANWbXrcAw@mail.gmail.com>
In-Reply-To: <CANpmjNMi3jQaqEB54ypWh2xEKCVRzBesMMfV0zZBcANWbXrcAw@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 14 Feb 2020 23:44:47 +0100
Message-ID: <CANpmjNP+q8UiySWXLrcMwvQ1fPPxo7=TtUbXizn_XjmK3L9fMQ@mail.gmail.com>
Subject: Re: KCSAN pull request content
To: Qian Cai <cai@lca.pw>, kasan-dev <kasan-dev@googlegroups.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Konovalov <andreyknvl@google.com>, Alexander Potapenko <glider@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=XC3OnI6J;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as
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

On Fri, 14 Feb 2020 at 23:40, Marco Elver <elver@google.com> wrote:
>
> +kasan-dev
>
> On Fri, 14 Feb 2020 at 23:07, Qian Cai <cai@lca.pw> wrote:
> >
> > On Fri, 2020-02-14 at 22:48 +0100, Marco Elver wrote:
> > > On Fri, 14 Feb 2020 at 20:51, Qian Cai <cai@lca.pw> wrote:
> > > >
> > > > On Fri, 2020-02-14 at 12:03 +0100, Marco Elver wrote:
> > > > > > > Lately, I have spent a few days reviewing the reports. There are still way too many
> > > > > > > likely false positives that really need ways to control them efficiently other than sending
> > > > > > > hundreds of patches using the data_race() macro. There are many places write and
> > > > > > > read only care about a single bit, i.e. page->flags that is safe from a data race.
> > > > >
> > > > > The bit operations are tricky. Just sending 'data_race()' doesn't fix
> > > > > too much per-se, so let's think about this.
> > > > >
> > > > > For now, filtering the marked atomic bit writes (like you have below)
> > > > > and unmarked reads, you may use the following config:
> > > > >    CONFIG_KCSAN_IGNORE_ATOMICS=y
> > > > >    CONFIG_KCSAN_REPORT_RACE_UNKNOWN_ORIGIN=n
> > > > > (The Kconfig defaults together with these 2 options should give you
> > > > > the most conservative reporting.)
> > > > >
> > > > > That would certainly get rid of all the marked flags writes (which I
> > > > > assume they should be) and unmarked read cases. Although I still don't
> > > > > fully agree that all the reads can be unmarked, for the time being
> > > > > let's assume that's the case.
> > > >
> > > > CONFIG_KCSAN_IGNORE_ATOMICS=y will not work in many places where the write is
> > > > only under a lock where there are many of them. For example,
> > > >
> > > > [  460.852674][  T765] write to 0xffff903d862d107c of 4 bytes by task 810 on cpu
> > > > 5:
> > > > [  460.860130][  T765]  css_killed_work_fn+0x9e/0x350
> > > > css_killed_work_fn+0x9e/0x350:
> > > > offline_css at kernel/cgroup/cgroup.c:5098
> > > > (inlined by) css_killed_work_fn at kernel/cgroup/cgroup.c:5385
> > > > [  460.864965][  T765]  process_one_work+0x54f/0xb90
> > > > [  460.869713][  T765]  worker_thread+0x80/0x5f0
> > > > [  460.874110][  T765]  kthread+0x1cd/0x1f0
> > > > [  460.878068][  T765]  ret_from_fork+0x27/0x50
> > > > [  460.882368][  T765]
> > > > [  460.884577][  T765] read to 0xffff903d862d107c of 4 bytes by task 765 on cpu
> > > > 103:
> > > > [  460.892114][  T765]  drain_stock+0x7a/0xd0
> > > > css_put_many at include/linux/cgroup.h:416
> > > > (inlined by) drain_stock at mm/memcontrol.c:2086
> > > > [  460.896245][  T765]  drain_local_stock+0x35/0x70
> > > > [  460.900899][  T765]  process_one_work+0x54f/0xb90
> > > > [  460.905640][  T765]  worker_thread+0x80/0x5f0
> > > > [  460.910031][  T765]  kthread+0x1cd/0x1f0
> > > > [  460.913985][  T765]  ret_from_fork+0x27/0x50
> > > >
> > > > The write is under cgroup_mutex to remove CSS_ONLINE bit but the reader only
> > > > care about CSS_NO_REF. Those still look safe to me.
> > >
> > > Right, at this point I'd say they are data races I'd expect to see.
> > > Simply because this one is safe, doesn't mean the next one is safe.
> > > Also we need to ask a few more questions here.
> > >
> > > What are the assumptions?
> > > Where can this function be called? What do we know about the callers?
> > > Do they use it in a loop?
> > > Are concurrent writes to this bit possible? If yes, we should
> > > definitely apply READ_ONCE.
> >
> > My observation is that the ratio of real issues vs false positives is really
> > low.
>
> False positive appears to be quite subjective when it comes to data
> races, and everybody has a different set of preferences. We know this,
> and KCSAN is already pretty configurable
>
> What is your definition of false positive?
>
> > > If not, you could apply ASSERT_EXCLUSIVE_BITS(css->flags, CSS_NO_REF).
> > > Looking at the code, this bit only seems to be set on init. Since this
> > > applies to all accesses of CSS_NO_REF, maybe a helper function to
> > > check if it's a ref-countable css?
> >
> > ASSERT_EXCLUSIVE_BITS() could work, but my observation I might need some courage
> >  first to send those patches to subsystem maintainers because most of them if
> > not all will be false positives and could easily test their temper. [1]
>
> One of our goals should be to mark enough intentional races
> (eliminating data races), so that at the end of the day, we're left
> with only the critical ones. Although right now, we're not there yet.
> This will take time and careful fixes over a longer period of time. We
> can't make all data races disappear in a week. The way I see it is
> that, the kernel has data races, and we need to understand them, but
> wanting a tool that just declares the kernel data race free is
> impossible, because the kernel clearly has a number of unsafe patterns
> that we need to investigate.
>
> There are 2 options for you: (1) keep sending patches, trying to keep
> up with data races as you see them; or (2)

[email transmission error, send to quick]

or (2) collect data races, filter them on your end, and for what you
consider most important, start sending patches.

I think (2) will be more worthwhile. That being said, we're constantly
looking to improve the "automatic" filtering, but as mentioned above,
preferences can be quite subjective.

> When you say that maintainers may be unwilling to accept patches, then
> I claim that only pertains to those where we haven't fully understood
> what is happening. The only patches I'm worried about are patches that
> include 'data_race()' or '__no_kcsan' (or KCSAN_SANITIZE_file.o := n).
> For all others, if the reasoning is solid, it should be an
> improvement.
>
> However: Concurrency is tricky. And it is all too easy to miss a
> number of cases, and that's when the patch should get scrutinized.
>
> > [1] https://lore.kernel.org/linux-arm-kernel/20190809090413.c57d7qlqgihdyzt6@wil
> > lie-the-truck/

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNP%2Bq8UiySWXLrcMwvQ1fPPxo7%3DTtUbXizn_XjmK3L9fMQ%40mail.gmail.com.
