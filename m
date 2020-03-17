Return-Path: <kasan-dev+bncBCMIZB7QWENRBBGWYTZQKGQEGSWIG6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id B1138188E66
	for <lists+kasan-dev@lfdr.de>; Tue, 17 Mar 2020 20:54:45 +0100 (CET)
Received: by mail-qt1-x837.google.com with SMTP id w3sf22457864qtc.8
        for <lists+kasan-dev@lfdr.de>; Tue, 17 Mar 2020 12:54:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1584474884; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ty+yApX6Blm/cl8icTKyTu2exHJ42ex6jh6ICmTvEi5SgqnNKaLCsurW+RWvcUr0nW
         RKrx4JxDMwLqUsMkkGPQZD3huRpguWKVLCg+scUJh0ICa0edM+Esyl+8OywkjuFlI2qD
         CRLWdmtCRAGdKEqOQFDuuyEk8xATe0bc8lkqyGVZyXAR0Nsmd6tnmtH9ztkQ3To3O+Jo
         qagPeXHncrMtWk3hwRHnLfS00x7DIQ/1o+V0lPegEoyEe0m2XMHlbbtCz024mcYEOA/0
         G7jXyx4HewVBRVz4FIB1FwUnfMc+WFrDuW1D5V85O1nXg8W3fc0Po5tGai9JTFX2pejy
         Ez8Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=LBcbY79WR06N+HK4EVhP4e0N8XUiInhdj/mhIEMBNfI=;
        b=Q5N4HCHBn1LmDHho7gOKvvVWlqq3ksWuYnOq59ndaEVDDfpMKsh/hLU+RBEldeN7id
         +3/zEjU1Gmh8w1j7VhXKvEnx4yyOIwuNts4UyFlOuKJR10pkO1D4Euso/Kvy6xg39KoB
         eZOzwzIIbSqEjW6w378I3VF1UlTe4vNv7V1YZTRJ+eJMTBtgZ1w8L+veUJ/N/+wYNxgs
         fthRQcudBlHyeDGyZ3fLkYsEf9E3qwQiNZ50g6N9GKQoW+1vZlWiK7P7L1aLV1iXsf3t
         HyOxp5sAdO5WIPQiECOs+cuiY1jzx+mXSZXu+WsIVAqtZnnL6sx3K0gcUd6fyhxspd7G
         P+Eg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=m7MfNqI7;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LBcbY79WR06N+HK4EVhP4e0N8XUiInhdj/mhIEMBNfI=;
        b=eXKtKEJNc0H40tWBZOqAJwbSlfeXZ/NbHlbrRX4aJ1bI2NOdo4knYzV+Lezu8qIENu
         ky9PRkGRPiWB+4Y7aTxkkSHPjtIcppoQMOsWshI4e9ekogu1HIEtvmVWM5QWnQxskIU9
         ITQF6sHZaLvMcoV0XW1euijn2kuJDuHex3+ocoDpXXMw9G4UgtOqt7hLtjJo/bmK/w7b
         NAp9CO9nn6wX8GUof713foEq5+8yzg06dvK9WGmJl4M/O+rWSomf+cRMvrNEXGCSKOz3
         tlotkyGz/bSNQ+0tLF3A9cMWNNJUjqj9ZRsQqwRym4GlV31KTvKEeXwjvB1PFUSrBLEi
         4nlQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LBcbY79WR06N+HK4EVhP4e0N8XUiInhdj/mhIEMBNfI=;
        b=iwCspdAjlqWsK66VjfFzgfNFqTYCgKyskRinB2bVwbKl6+N9l9BYGHzCKBNbgfil3Y
         gyy9sj7Jj90X+jDqz5pcowOvMkiNOESpkgyW7wPqj3MhsFuTjJlqhfj6oMCTwaEDQI0Z
         CX0RU5MNn5RRpC+In883zLmtu+y/LB4N2XJV4MlEyJU4SpGkTpxs8zBW9W7WrFaaH4eK
         k0n75VFUAwkoh+1mxzc7mCez+X0+Enh8AK3G/wpb8K0dUd1EVRm8KItUDjxsy5Z0pWpV
         /8F1OGzqyub/rc63w2awjF8qF96bVeUbbHW/pXRXNQFp2U/UjzdVoTEVYyzfg+4BL4/f
         tglA==
X-Gm-Message-State: ANhLgQ0eXXb7DTPueEdBDEDg0R/Qa7Nl/C/TCdK6e40suIv5Wf2cUvDN
	Qg3ZMpVpg5g/yYd+BCpu/rY=
X-Google-Smtp-Source: ADFU+vsTRSDhQvAqdJYelBTq9MNkmGkmugYGHo29p8sZnd7GhFah2a//jyWTuZChwl3hOAXnH8heIA==
X-Received: by 2002:a25:9d86:: with SMTP id v6mr478829ybp.263.1584474884745;
        Tue, 17 Mar 2020 12:54:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:2397:: with SMTP id j145ls2677856ybj.6.gmail; Tue, 17
 Mar 2020 12:54:44 -0700 (PDT)
X-Received: by 2002:a25:bb4f:: with SMTP id b15mr512174ybk.175.1584474884381;
        Tue, 17 Mar 2020 12:54:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1584474884; cv=none;
        d=google.com; s=arc-20160816;
        b=Qd84vPuhEGbCkOtq4WRaAvalFQNxvuZl1U5bkyp9QAE2Aw01E4r5fNelbi5j3b/d5p
         y/j/uSvr20XCQuqsTWaKoaC8zVxufGaH4ed222tS4ielXoKSB7klwWY7FQ4n/PMiYZEP
         JDarkjHgBqxMe2wE88/ALEaIuIIe7X23p4eyRmqJNHXducEKi0xlIdoIaq0xSTt5xJfV
         3+AhjDjgtk4qEDDugIYHkPgON2DBjK1OXroaflaLajMMHJwk/pPo9837OoQ1ZNjNNitD
         XvAVWIIKHtrucYs5UJ2t6ufxDilxCrp1b8Zlq5RA1IqmmE1VQmbgvd6iRMMb3jDCuEEE
         9i4w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=17f/5HAzacgo37aOQY2l5ZAXL11rooxUDN7MpTirpco=;
        b=jD9UI71fnScRSG90PX5S9fm+i+Cg12JM7wDuw6V2l7PnGZzYx3GarCPg5G1b85D2JK
         lvV2nkJHxpIUXseVhLlK/q6zmKFv0D/UoPatnNNsmWDQ9DCWK5G2uJKuaWu4p/6hx6nz
         u741yUdvPf9SEeV+OTr0ob0RSPUCw/CuMh/QUEpJDaNTaHrmiE6tnwJefg5IEOo6R5uq
         wNVrEdwkllzXOOlGV8xal0TQnOyxIIA2Tckum14k+f/Y8feApichoRcugrYkR5SWzFTf
         HBqhL8/xKn+hNUPWmIqeKsyp5RBvSkayGwusEKOMIGLRVvR4rzt5ta+za0kUgZAk4bAA
         OIPA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=m7MfNqI7;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x842.google.com (mail-qt1-x842.google.com. [2607:f8b0:4864:20::842])
        by gmr-mx.google.com with ESMTPS id 207si272266ybe.5.2020.03.17.12.54.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 17 Mar 2020 12:54:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842 as permitted sender) client-ip=2607:f8b0:4864:20::842;
Received: by mail-qt1-x842.google.com with SMTP id d22so18676110qtn.0
        for <kasan-dev@googlegroups.com>; Tue, 17 Mar 2020 12:54:44 -0700 (PDT)
X-Received: by 2002:aed:38c8:: with SMTP id k66mr928098qte.50.1584474883559;
 Tue, 17 Mar 2020 12:54:43 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1582216144.git.leonard.crestez@nxp.com> <10e97a04980d933b2cfecb6b124bf9046b6e4f16.1582216144.git.leonard.crestez@nxp.com>
 <158264951569.54955.16797064769391310232@swboyd.mtv.corp.google.com>
 <VI1PR04MB70233A098DC4A2A82B114E93EEED0@VI1PR04MB7023.eurprd04.prod.outlook.com>
 <158276809953.177367.6095692240077023796@swboyd.mtv.corp.google.com> <VI1PR04MB6941383E77EC501E96D2CBB0EEF60@VI1PR04MB6941.eurprd04.prod.outlook.com>
In-Reply-To: <VI1PR04MB6941383E77EC501E96D2CBB0EEF60@VI1PR04MB6941.eurprd04.prod.outlook.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 17 Mar 2020 20:54:31 +0100
Message-ID: <CACT4Y+Yqrx+GXF9+_oPY+4HXhufN=eoghUcimSzhWsQbLz75wg@mail.gmail.com>
Subject: Re: [PATCH v2 1/8] clk: imx: Align imx sc clock msg structs to 4
To: Leonard Crestez <leonard.crestez@nxp.com>
Cc: Stephen Boyd <sboyd@kernel.org>, Shawn Guo <shawnguo@kernel.org>, 
	Aisheng Dong <aisheng.dong@nxp.com>, Fabio Estevam <fabio.estevam@nxp.com>, 
	Michael Turquette <mturquette@baylibre.com>, Stefan Agner <stefan@agner.ch>, 
	Linus Walleij <linus.walleij@linaro.org>, Alessandro Zummo <a.zummo@towertech.it>, 
	Alexandre Belloni <alexandre.belloni@bootlin.com>, Anson Huang <anson.huang@nxp.com>, 
	Abel Vesa <abel.vesa@nxp.com>, Franck Lenormand <franck.lenormand@nxp.com>, 
	dl-linux-imx <linux-imx@nxp.com>, "linux-clk@vger.kernel.org" <linux-clk@vger.kernel.org>, 
	"linux-arm-kernel@lists.infradead.org" <linux-arm-kernel@lists.infradead.org>, 
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=m7MfNqI7;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Tue, Mar 17, 2020 at 8:25 PM Leonard Crestez <leonard.crestez@nxp.com> wrote:
>
> On 2020-02-27 3:48 AM, Stephen Boyd wrote:
> > Quoting Leonard Crestez (2020-02-25 11:52:11)
> >> On 25.02.2020 18:52, Stephen Boyd wrote:
> >>> Quoting Leonard Crestez (2020-02-20 08:29:32)
> >>>> The imx SC api strongly assumes that messages are composed out of
> >>>> 4-bytes words but some of our message structs have odd sizeofs.
> >>>>
> >>>> This produces many oopses with CONFIG_KASAN=y.
> >>>>
> >>>> Fix by marking with __aligned(4).
> >>>>
> >>>> Fixes: fe37b4820417 ("clk: imx: add scu clock common part")
> >>>> Signed-off-by: Leonard Crestez <leonard.crestez@nxp.com>
> >>>> ---
> >>>>    drivers/clk/imx/clk-scu.c | 6 +++---
> >>>>    1 file changed, 3 insertions(+), 3 deletions(-)
> >>>>
> >>>> diff --git a/drivers/clk/imx/clk-scu.c b/drivers/clk/imx/clk-scu.c
> >>>> index fbef740704d0..3c5c42d8833e 100644
> >>>> --- a/drivers/clk/imx/clk-scu.c
> >>>> +++ b/drivers/clk/imx/clk-scu.c
> >>>> @@ -41,16 +41,16 @@ struct clk_scu {
> >>>>    struct imx_sc_msg_req_set_clock_rate {
> >>>>           struct imx_sc_rpc_msg hdr;
> >>>>           __le32 rate;
> >>>>           __le16 resource;
> >>>>           u8 clk;
> >>>> -} __packed;
> >>>> +} __packed __aligned(4);
> >>>
> >>> Sorry, this still doesn't make sense to me. Having __aligned(4) means
> >>> that the struct is placed on the stack at some alignment, great, but it
> >>> still has __packed so the sizeof this struct is some odd number like 11.
> >>> If this struct is the last element on the stack it will end at some
> >>> unaligned address and the mailbox code will read a few bytes beyond the
> >>> end of the stack.
> >>
> >> I checked again and marking the struct with __aligned(4) makes it have
> >> sizeof == 12 as intended. It was 11 before.
> >>
> >>       static_assert(sizeof(struct imx_sc_msg_req_set_clock_rate) == 12);
> >>
> >> After reading through your email and gcc docs again I'm not sure if this
> >> portable/reliable this is but as far as I understand "sizeof" needs to
> >> account for alignment. Or is this just an accident with my compiler?
> >>
> >> Marking a structure both __packed and __aligned(4) means that __packed
> >> only affects internal struct member layout but sizeof is still rounded
> >> up to a multiple of 4:
> >>
> >> struct test {
> >>          u8      a;
> >>          u16     b;
> >> } __packed __aligned(4);
> >>
> >> static_assert(sizeof(struct test) == 4);
> >> static_assert(offsetof(struct test, a) == 0);
> >> static_assert(offsetof(struct test, b) == 1);
> >>
> >> This test is not realistic because I don't think SCU messages have any
> >> such oddly-aligned members.
> >>
> >
> > I'm not really sure as I'm not a linker expert. I'm just especially wary
> > of using __packed or __aligned attributes because they silently generate
> > code that is usually inefficient. This is why we typically do lots of
> > shifting and masking in the kernel, so that we can easily see how
> > complicated it is to pack bits into place. Maybe it makes sense to get
> > rid of the structs entirely and pack the bits into __le32 arrays of
> > varying length. Then we don't have to worry about packed or aligned or
> > what the compiler will do and we can easily be confident that we've put
> > the bits in the right place in each u32 that is eventually written to
> > the mailbox register space.
>
> These message structs are not as complicated as hardware register, for
> example everything is always on a byte border.
>
> In older versions of the imx internal tree SC messaging is done by
> packing into arrays through a layer of generated code which looks like this:
>
>           RPC_VER(&msg) = SC_RPC_VERSION;
>           RPC_SVC(&msg) = U8(SC_RPC_SVC_MISC);
>           RPC_FUNC(&msg) = U8(MISC_FUNC_SET_CONTROL);
>           RPC_U32(&msg, 0U) = U32(ctrl);
>           RPC_U32(&msg, 4U) = U32(val);
>           RPC_U16(&msg, 8U) = U16(resource);
>           RPC_SIZE(&msg) = 4U;
>
> The RPC_U32/U16 macros look like this:
>
> #define RPC_I32(MESG, IDX)      ((MESG)->DATA.i32[(IDX) / 4U])
> #define RPC_I16(MESG, IDX)      ((MESG)->DATA.i16[(IDX) / 2U])
> #define RPC_I8(MESG, IDX)       ((MESG)->DATA.i8[(IDX)])
> #define RPC_U32(MESG, IDX)      ((MESG)->DATA.u32[(IDX) / 4U])
> #define RPC_U16(MESG, IDX)      ((MESG)->DATA.u16[(IDX) / 2U])
> #define RPC_U8(MESG, IDX)       ((MESG)->DATA.u8[(IDX)])
>
> and the message struct itself has a big union for the data:
>
> typedef struct {
>           uint8_t version;
>           uint8_t size;
>           uint8_t svc;
>           uint8_t func;
>           union {
>                   int32_t i32[(SC_RPC_MAX_MSG - 1U)];
>                   int16_t i16[(SC_RPC_MAX_MSG - 1U) * 2U];
>                   int8_t i8[(SC_RPC_MAX_MSG - 1U) * 4U];
>                   uint32_t u32[(SC_RPC_MAX_MSG - 1U)];
>                   uint16_t u16[(SC_RPC_MAX_MSG - 1U) * 2U];
>                   uint8_t u8[(SC_RPC_MAX_MSG - 1U) * 4U];
>           } DATA;
> } sc_rpc_msg_t;
>
> This approach is very verbose to the point of being unreadable I think
> it's much to message structs instead. Compiler struct layout rules are
> not really all that complicated and casting binary data as structs is
> very common in areas such as networking. This approach is also used by
> other firmware interfaces like TI sci and nvidia bpmp.
>
> imx8 currently has manually written message structs, it's unfortunate
> that a bug was found and fixing required a scattering patches in
> multiple subsystems. Perhaps a better solution would be to centralize
> all structs in a single header similar to drivers/firmware/ti_sci.h?
>
> In order to ensrue that there are no issues specific to the compile
> version perhaps a bunch of static_assert statements could be added to
> check that sizeof and offset are as expected?
>
> ---------------------------------
>
> As far as I can tell the issue KASAN warns about can be simplified to this:
>
> struct __packed badpack {
>      u32     a;
>      u16     b;
>      u8      c;
> };
>
> static_assert(sizeof(struct badpack) == 7);
>
> static void func(void *x)
> {
>      u32* arr = (u32*)x;
>      arr[0] = 0x11111111;
>      arr[1] = 0x22222222;
> }
>
> static int hello(void)
> {
>      struct badpack s;
>      u8 x = 0x33;
>
>      printk("&s=%px &x=%px\n", &s, &x);
>      func(&s);
>      // x could be overwritten here, depending on stack layout.
>      BUG_ON(x != 0x33);
>
>      return 0;
> }
>
> Adding __aligned(4) bumps struct size to 8 and avoids the issue
>
> Added KASAN maintainers to check if this is a valid fix.

Hi Leonard,

I think it should fix the bug.
It's not so much about KASAN, more about the validity of the C program.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYqrx%2BGXF9%2B_oPY%2B4HXhufN%3DeoghUcimSzhWsQbLz75wg%40mail.gmail.com.
