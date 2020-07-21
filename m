Return-Path: <kasan-dev+bncBDE6RCFOWIARBG5W3L4AKGQEQQ6P6JY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 514BD227991
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Jul 2020 09:37:00 +0200 (CEST)
Received: by mail-lj1-x23d.google.com with SMTP id r9sf4901824ljj.10
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Jul 2020 00:37:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1595317020; cv=pass;
        d=google.com; s=arc-20160816;
        b=CRwOdkHKLNYDg43wYUzTQdapRZYKlaxVna95k7R8WBuQnMawZkBwrkkh/0xkCoOkqg
         CtfjQ456Kqqi09o3PPTqtXp0kOETit8JuqRCj2uJJRSKo8OiUYyQRS/cTYp31nQrHtiw
         amm7tqcbCK4XrhlS9IAcw/fHwgBXCUsWo4L1/0QmUBUVuz6v0I/QTL0TfOVbZJaIsylX
         mgNL/qWHjnczczCFq4cO6/k7S2M5Cwp7QH0tvLxxXXuHJgvgqYWsQQ+u9MdX0wpcIH4W
         9yUT5rRMUFdiGUGPD9pWX9wZFerUEYHBFUGLOcV9IZcAcH0BYGRmscZz0zT4jukDQdNc
         EvQQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=EpTvSp+xsBHKBO8VqXe+17eO1DjZfAxRYqMlh95sols=;
        b=WY86vXf2WK+cpHMz5Q8BsiXD5/xBMRNh3RbZbktec/L+qCT/6ZB/kSPntKMl1myHgK
         py+1g+KN1dw4oZj2RCyz0w1Xloy8zshN0pj1tb7XzUhxRzzGscieDiX004ytIitNE7CA
         S3LddD7j1hg5qG17qnbIGvxpdCbCGWjFwIXJSHvM13Gjyk7aCq61awoxN7+uORodA1oV
         UbgAEkxSD2NaINC4FenGufLv8A6rC+9FVm3HzDJDCxYZ0fA/3PZteDGO4Ja0AmE8gnk1
         6e1oXqo2wWQIX6WtY7Xiqpa3oyUuOlik5L538484Qn4dGlx7mHh7rPqnsJuAYFZCTrwm
         yL1w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=mN2QG29f;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::244 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EpTvSp+xsBHKBO8VqXe+17eO1DjZfAxRYqMlh95sols=;
        b=hxIa6LxYQXVndmT/zwA0oFcGlWz6b8z0HCVttUu7vu0jcpgQFT3P7QieFM1MFJl2XL
         hCM1mRjobpTG51cZFyGlRIJwmM2g7+xzZOpIWSp0U09gUzaUgxBAcavks5ReK5kjp4q6
         qgr9swjSRZ29lEfHOAMWBxb8/9JoBUi06lfKncSuY515Gr7oJ04G6bcbIsUrhap6LwIg
         yVU+6HyyohMxRo7LDcVtZeQbDZ8TE125OaRsj6v11QZ0CI9trE+/PXUNE9+6LX1FelHd
         26Ct5SpdRyv38guEpFOQq2mUaNm3kOgRUg3f3NcFf6b+m+ESUwGB93O2780yQXPKzeau
         kIVw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EpTvSp+xsBHKBO8VqXe+17eO1DjZfAxRYqMlh95sols=;
        b=aNLHxwjknj0u1M4UlOjgU6al8GmFyKSFwdw5RAGLVIIIUmkjOiKcNJuNlqDrXp3l6/
         VJ4jiA7bJ4dNAJ3b0uCaX8OZqtT7PAzl1GYwUEvsr2KAEL+TBEj6iPNNjE5kmsSlv87s
         lqhZWCksZ/AwiaJAt0qiEKRYJIP7VpBW5vHu3A/08EbBuxUQZcEq4Ni6jNz4ZoCd7LHh
         h93DWREylOwP8OiNRy9bgViZxGIupWSGmmuGsgq5g6zt7zqcqavhEB/80m2NbIaQBbjr
         mrWmoHY8No58kFJ2tzDUy7bvvoKx1lK4l7KxQjiarOZhtiOnlHr9vkFokMo7zMX4BAn8
         gdBw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532isFxEsHlwcBX12y7IrWercn+PtpeD7B+dd3nVhfYfFpf/6x/W
	mNxJvJSJd/Bp75uURmr4IHs=
X-Google-Smtp-Source: ABdhPJwobDA9zNvFyXkHgXnyaTmrMqnhQ8kEsWdFYHrpqnZDzsVAuhbeXU/VrNe9iw//Zzyg9JMZfQ==
X-Received: by 2002:a2e:b0f0:: with SMTP id h16mr12768163ljl.167.1595317019841;
        Tue, 21 Jul 2020 00:36:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:230:: with SMTP id z16ls3129851ljn.4.gmail; Tue, 21
 Jul 2020 00:36:59 -0700 (PDT)
X-Received: by 2002:a2e:815a:: with SMTP id t26mr12720335ljg.182.1595317019203;
        Tue, 21 Jul 2020 00:36:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1595317019; cv=none;
        d=google.com; s=arc-20160816;
        b=uAI0qd2O2531xdIKCFkXqtsSh25iRNHdz/pcDorUyqr2PReSE4Wsh89fSRBNoQg4HP
         4xMhCIqsb5Bw4yJgHMI/BSf7+9D11DGyZaZeF9uq2WmcfKMgzG/wkbm+f5ry8q6NKN4i
         0lNRMYFmYEtkyQoiIa3tybaVTQUrys0PkIUxUtK6/hmYe/YPR4GRCj8OQ9zAGvsqEK7B
         Fz5lU82Fui55qBlqL8oqu/FnASlxT4XT7d3Y/qnJVQFikujfWcrvID7y3J/HR+z5YLq/
         EriSPmS7pKnfXDmFpftBFFgnUmTGq0SEp/JRTTXQBQmWFahRCzgwuvqv4zXLgH4yxeLF
         e0zA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=1i104sQjFmmUo1k6PxY+qJurpeA5ObR4NFti+DsXWNM=;
        b=RVl0bgUzHHiQS05sk/qBFbzwEhq2CPADauvfkpBdEHp1Cp65tbjipUD79PsgouXOMA
         YKX8fJU2wuNgjquJU4Uddjears0rOfjmArbatx32gkiVb4vhjUZnZAsJAxhJqTygJheC
         gHcmWvxs/I65It11qeXnfatI3IZqtmyDuu1YEeg4/csaoBI82oDiv1oNmcG4WI4lZ0T3
         UcZzEsY+7hf03VNTDkGUxdmHCssuYcXtJ/JDueMCfBzJ/gqFTRiVnVdrNhqI375EJuou
         ydFhPQ9cXB2RTHpNkwLsevtaIhly5mVziR90NLDyLYbKO9TuwHvKpwOF2/hz0c+uL6wF
         j+zQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=mN2QG29f;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::244 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lj1-x244.google.com (mail-lj1-x244.google.com. [2a00:1450:4864:20::244])
        by gmr-mx.google.com with ESMTPS id z26si668712lfe.5.2020.07.21.00.36.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 21 Jul 2020 00:36:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::244 as permitted sender) client-ip=2a00:1450:4864:20::244;
Received: by mail-lj1-x244.google.com with SMTP id d17so23006110ljl.3
        for <kasan-dev@googlegroups.com>; Tue, 21 Jul 2020 00:36:59 -0700 (PDT)
X-Received: by 2002:a2e:8046:: with SMTP id p6mr12838240ljg.100.1595317018810;
 Tue, 21 Jul 2020 00:36:58 -0700 (PDT)
MIME-Version: 1.0
References: <CACRpkdYbbtJFcAugz6rBMHNihz3pnY9O4mVzwLsFY_CjBb9K=A@mail.gmail.com>
 <78f24add-530c-5395-ea7d-770bfba85c5a@gmail.com>
In-Reply-To: <78f24add-530c-5395-ea7d-770bfba85c5a@gmail.com>
From: Linus Walleij <linus.walleij@linaro.org>
Date: Tue, 21 Jul 2020 09:36:46 +0200
Message-ID: <CACRpkdYBhJnZQtaSmtHc_yUMf6=WD72=hOiZ2Z2DL5uKsQiU=g@mail.gmail.com>
Subject: Re: [GIT PULL] KASan for Arm, v12
To: Florian Fainelli <f.fainelli@gmail.com>
Cc: Russell King <linux@armlinux.org.uk>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=mN2QG29f;       spf=pass
 (google.com: domain of linus.walleij@linaro.org designates
 2a00:1450:4864:20::244 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
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

On Mon, Jul 20, 2020 at 8:01 PM Florian Fainelli <f.fainelli@gmail.com> wrote:

> I am still seeing crashes similar to the ones reported before with this
> pull request, but maybe we can get it merged and address it later on
> since this has been waiting forever to be merged.

We definitely need it fixed, my current working assumption is that at
least some of it is a result of the kernel growing big as a result of
enabling KASan.

Can you try to inspect the early memblock.memory.regions[0]
mapping debug prints as I pointed out here:
https://lore.kernel.org/linux-arm-kernel/CACRpkdYoMiVtnQEUiXy3Ezf3Z0dEQSVyA-9emDeewRKwonoUHQ@mail.gmail.com/#t

On the APQ8060 it seems the first memblock does not fit the
kernel+attached devicetree and the devicetree ends up in the
unmapped memory that is cleared by prepare_page_table()
but the Broadcom problem may be another one altogether.

Yours,
Linus Walleij

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACRpkdYBhJnZQtaSmtHc_yUMf6%3DWD72%3DhOiZ2Z2DL5uKsQiU%3Dg%40mail.gmail.com.
